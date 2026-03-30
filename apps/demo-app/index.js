const express = require('express');
const { exec } = require('child_process');
const fs = require('fs');
const http = require('http');

const app = express();
app.use(express.json());

// Endpoints are intentionally vulnerable to demonstrate RASP protection

// 1. SQL Injection 
app.get('/vuln/sqli', (req, res, next) => {
    const id = req.query.id;
    const { Client } = require('pg');
    const client = new Client();
    try {
        // VULNERABLE: Direct string concatenation into a database query
        client.query(`SELECT * FROM users WHERE id = '${id}'`);
    } catch (e) {
        if (e.name === 'SecurityBlockException') return next(e);
        // Ignore standard DB connection errors since we don't have a real DB
    }

    res.json({ message: "Executed query", sql: `SELECT * FROM users WHERE id = '${id}'` });
});

// 2. Command Injection
app.get('/vuln/cmd', (req, res) => {
    const host = req.query.host;
    // VULNERABLE: Direct string concatenation into a shell command
    exec(`ping -c 1 ${host}`, (err, stdout, stderr) => {
        res.json({ stdout, stderr });
    });
});

// 3. Remote Code Execution
app.get('/vuln/rce', (req, res, next) => {
    const code = req.query.code;
    // VULNERABLE: Executing arbitrary code from user input
    try {
        const result = eval(code);
        res.json({ result });
    } catch (e) {
        next(e);
    }
});

// 4. Path Traversal
app.get('/vuln/path', (req, res, next) => {
    const file = req.query.file;
    // VULNERABLE: Unsanitized file path access
    try {
        fs.readFile(file, 'utf8', (err, data) => {
            if (err) return res.status(500).json({ error: err.message });
            res.send(data);
        });
    } catch (e) {
        next(e);
    }
});

// 5. Prototype Pollution
app.post('/vuln/prototype', (req, res, next) => {
    // VULNERABLE: Parsing JSON without validation can pollute prototypes
    try {
        // Force the parse to hit the global hook if Express body-parser didn't
        JSON.parse(JSON.stringify(req.body));
        res.json({ status: "processed", payload: req.body });
    } catch (e) {
        next(e);
    }
});

// 6. SSRF
app.get('/vuln/ssrf', (req, res, next) => {
    const url = req.query.url;
    // VULNERABLE: Requesting arbitrary URLs provided by the user
    try {
        http.get(url, (response) => {
            res.json({ statusCode: response.statusCode });
        }).on('error', (e) => {
            if (e.name === 'SecurityBlockException') return next(e);
            res.status(500).json({ error: e.message });
        });
    } catch (e) {
        next(e);
    }
});

// 7. NoSQL Injection
app.get('/vuln/nosql', (req, res, next) => {
    const filter = req.query.filter;
    // VULNERABLE: Unsanitized object filter for MongoDB
    const { Collection } = require('mongodb');
    try {
        const query = JSON.parse(filter);
        const col = Object.create(Collection.prototype);
        col.find(query);
    } catch (e) {
        if (e.name === 'SecurityBlockException') return next(e);
    }

    res.json({ message: "NoSQL Query executed", filter });
});

app.get('/health', (req, res) => res.json({ status: "ok" }));

// 🛡️ Global Security Exception Handler
app.use((err, req, res, next) => {
    if (err.name === 'SecurityBlockException') {
        console.warn(`[ShieldRASP] Blocked Request: ${err.message}`);
        return res.status(403).json({
            error: "Forbidden",
            message: "Request blocked by ShieldRASP Security Engine",
            details: err.details
        });
    }
    console.error(err);
    res.status(500).json({ error: "Internal Server Error" });
});

const port = 8081;
app.listen(port, () => {
    console.log(`\n🚀 Demo app listening on port ${port}`);
    console.log(`Test SQLi: curl "http://localhost:8081/vuln/sqli?id=1' OR 1=1--"`);
});
