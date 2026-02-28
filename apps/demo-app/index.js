require('@shieldrasp/node-agent').init({
    apiKey: process.env.RASP_KEY || 'demo_agent_key_12345',
    mode: process.env.RASP_MODE || 'protect',
    endpoint: process.env.RASP_URL || 'localhost:50051'
});

const express = require('express');
const { exec } = require('child_process');
const { Client } = require('pg');
const app = express();

app.use(express.json());

// Dummy Postgres connection
const client = new Client({
    connectionString: process.env.DATABASE_URL || 'postgresql://shieldrasp:password@localhost:5432/shieldrasp'
});
client.connect().catch(() => console.log("DB unconnected - ignoring for demo"));

app.get('/vuln/sqli', async (req, res) => {
    const id = req.query.id;
    try {
        const result = await client.query(`SELECT * FROM users WHERE id = ${id}`);
        res.json(result.rows);
    } catch (error) {
        if (error.name === 'RASPBlockError') {
            return res.status(403).json({ error: 'Blocked by ShieldRASP', details: error.message });
        }
        res.status(500).json({ error: 'DB Error' });
    }
});

app.post('/vuln/cmd', (req, res) => {
    const host = req.body.host;
    try {
        exec(`ping -c 1 ${host}`, (err, stdout, stderr) => {
            res.send(`<pre>${stdout}</pre>`);
        });
    } catch (error) {
        if (error.name === 'RASPBlockError') {
            return res.status(403).json({ error: 'Blocked by ShieldRASP', details: error.message });
        }
        res.status(500).json({ error: 'Command Execution Error' });
    }
});

app.listen(8080, () => console.log('Demo app listening on port 8080. Test: curl "http://localhost:8080/vuln/sqli?id=1 UNION SELECT * FROM secrets"'));
