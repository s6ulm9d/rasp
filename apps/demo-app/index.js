if (process.env.NODE_ENV !== 'production') {
    require('@shieldrasp/agent').start({
        mode: 'block'
    });
}
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

app.get('/vuln/cmd', (req, res) => {
    const host = req.query.host;
    try {
        exec(`ping -n 1 ${host}`, (err, stdout, stderr) => {
            res.send(`<pre>${stdout}</pre>`);
        });
    } catch (error) {
        if (error.name === 'RASPBlockError') {
            return res.status(403).json({ error: 'Blocked by ShieldRASP', details: error.message });
        }
        res.status(500).json({ error: 'Command Execution Error' });
    }
});

app.listen(8081, () => console.log('Demo app listening on port 8081. Test: curl "http://localhost:8081/vuln/sqli?id=1 UNION SELECT * FROM secrets"'));
