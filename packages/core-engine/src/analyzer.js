const url = require('url');
const querystring = require('querystring');
const Busboy = require('busboy');
const { DetectionEngine } = require('./detector');
const { Normalizer } = require('./normalizer');

class Inspector {
  constructor(policy) {
    this.policy = policy;
    this.detector = new DetectionEngine(policy);
    this.normalizer = new Normalizer();
  }

  preFlightCheck(req) {
     // Check headers and URL before body reconstruction
     const normalizedURL = this.normalizer.decodeURL(req.url);
     const normalizedHeaders = this.normalizer.normalizeMap(req.headers);
     
     const results = this.detector.scanHeaderAndURL({
        url: normalizedURL,
        headers: normalizedHeaders,
        ip: req.socket.remoteAddress
     });

     if (results.blocked) {
        return { blocked: true, reason: results.reason };
     }
     return { blocked: false };
  }

  async deepInspect(req, bodyBuffer) {
    // 1. Gather all inputs
    const inputs = {
       query: this.normalizer.normalizeMap(url.parse(req.url, true).query),
       headers: this.normalizer.normalizeMap(req.headers),
       body: {},
       files: [],
       rawBody: bodyBuffer ? bodyBuffer.toString('utf8', 0, 8192) : '' // Bound sample for raw inspection
    };

    // 2. Parse Body if present
    if (bodyBuffer) {
       const contentType = req.headers['content-type'] || '';
       
       if (contentType.includes('application/json')) {
          try {
             const json = JSON.parse(bodyBuffer.toString());
             inputs.body = this.normalizer.normalizeAnything(json);
          } catch (e) {
             // Fallback to raw string scanning if JSON parser chokes.
             inputs.body = { raw: this.normalizer.normalizeAnything(bodyBuffer.toString()) };
          }
       } else if (contentType.includes('multipart/form-data')) {
          const multipartData = await this._parseMultipart(req, bodyBuffer);
          inputs.body = this.normalizer.normalizeMap(multipartData.fields);
          inputs.files = multipartData.files; // Scan filenames and metadata
       } else if (contentType.includes('application/x-www-form-urlencoded')) {
          const parsed = querystring.parse(bodyBuffer.toString());
          inputs.body = this.normalizer.normalizeMap(parsed);
       } else {
          // Default: Scan as raw string for other types (text/plain, etc)
          inputs.body = { raw: this.normalizer.normalizeAnything(bodyBuffer.toString()) };
       }
    }

    // 3. Flatten and Scan
    const fullNormalizedInput = {
       ...inputs.query,
       ...inputs.headers,
       ...inputs.body
    };

    // Include file names in scanning
    inputs.files.forEach(f => {
       fullNormalizedInput[`file_${f.fieldname}`] = f.filename;
    });

    // RECONSTRUCT FULL CONTEXT to prevent fragmented/multi-field bypass
    fullNormalizedInput['FULL_COMBINED_PAYLOAD'] = JSON.stringify({
        query: inputs.query,
        headers: inputs.headers,
        body: inputs.body,
        files: inputs.files
    });

    const results = this.detector.scan(fullNormalizedInput, req.socket.remoteAddress);
    
    if (results.blocked) {
       return { blocked: true, reason: results.reason };
    }

    return { blocked: false };
  }

  _parseMultipart(req, bodyBuffer) {
     return new Promise((resolve) => {
        const busboy = Busboy({ headers: req.headers });
        const result = { fields: {}, files: [] };
        
        busboy.on('field', (name, val) => {
           result.fields[name] = val;
        });
        
        busboy.on('file', (name, file, info) => {
           const { filename, encoding, mimeType } = info;
           result.files.push({ fieldname: name, filename, encoding, mimeType });
           file.resume(); // We don't necessarily store the files for RASP unless deep scanning content
        });

        busboy.on('finish', () => {
           resolve(result);
        });

        // Write the reconstructed buffer to busboy
        busboy.end(bodyBuffer);
     });
  }
}

module.exports = { Inspector };
