const fs = require('fs');
const path = require('path');

class PolicyManager {
  constructor(filePath = path.join(process.cwd(), 'shieldrasp.policy.json')) {
    this.filePath = filePath;
    this.policy = {
       max_body_size: 5 * 1024 * 1024,
       block_threshold: 1.0,
       allow_userinfo: false,
       mode: 'block'
    };
    this._load();
    this._watch();
  }

  get(key) {
    return this.policy[key];
  }

  _load() {
    try {
      if (fs.existsSync(this.filePath)) {
        const data = fs.readFileSync(this.filePath, 'utf8');
        const parsed = JSON.parse(data);
        this.policy = { ...this.policy, ...parsed };
        console.log('[ShieldRASP] Policy Loaded Successfully.');
      } else {
        console.warn(`[ShieldRASP] Policy file ${this.filePath} not found. Using defaults.`);
        // Create default?
        fs.writeFileSync(this.filePath, JSON.stringify(this.policy, null, 2));
      }
    } catch (e) {
      console.error('[ShieldRASP] Critical Failure loading policy:', e.message);
    }
  }

  _watch() {
     // Watch for changes (throttle to avoid multi-events)
     let timer = null;
     fs.watch(this.filePath, (event) => {
        if (event === 'change') {
           if (timer) clearTimeout(timer);
           timer = setTimeout(() => {
              this._load();
              console.log('[ShieldRASP] Dynamic Policy Reload: Active.');
           }, 200);
        }
     });
  }
}

module.exports = { PolicyManager };
