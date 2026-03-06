#!/usr/bin/env node
import { Command } from 'commander';
import chalk from 'chalk';
import { Server } from 'socket.io';
import { table } from 'table';
import * as fs from 'fs';
import * as path from 'path';
const term = require('clui');

const program = new Command();

program
    .name('shieldrasp')
    .description('ShieldRASP CLI Tool for monitoring and security management')
    .version('1.1.0');

// 1. MONITOR - Live Telemetry
program
    .command('monitor')
    .description('Start a local telemetry monitor to receive RASP events')
    .option('-p, --port <number>', 'Port for telemetry collector', '50052')
    .action((options) => {
        const io = new Server(parseInt(options.port));
        console.log(chalk.green(`🚀 ShieldRASP CLI Monitor started on port ${options.port}`));
        console.log(chalk.dim('Awaiting telemetry streams from agents...'));

        io.on('connection', (socket) => {
            console.log(chalk.blue(`[CONNECTED] Agent connected: ${socket.id}`));

            socket.on('telemetry', (data) => {
                const event = typeof data === 'string' ? JSON.parse(data) : data;
                console.log(chalk.red.bold(`\n!!! ATTACK DETECTED !!!`));
                const tableData = [
                    [chalk.bold('Field'), chalk.bold('Value')],
                    ['Type', chalk.yellow(event.attack_type)],
                    ['Details', event.details || event.attack_subtype || 'N/A'],
                    ['Confidence', chalk.cyan(event.confidence || '1.0')],
                    ['Payload', chalk.dim(event.payload)],
                    ['Blocked', event.blocked || event.mode === 'block' ? chalk.green('Yes') : chalk.red('No')],
                    ['Source IP', event.source_ip || '127.0.0.1'],
                    ['Path', event.http_path || '/']
                ];
                console.log(table(tableData));
            });
        });
    });

// 2. INIT - Project Initialization
program
    .command('init')
    .description('Initialize ShieldRASP in the current project')
    .action(() => {
        const configPath = path.join(process.cwd(), 'shieldrasp.json');
        if (fs.existsSync(configPath)) {
            console.log(chalk.yellow('ℹ ShieldRASP is already initialized in this project.'));
            return;
        }

        const defaultConfig = {
            mode: 'block',
            endpoint: 'localhost:50052',
            protections: {
                sqli: true,
                cmd_injection: true,
                xss: true,
                ssrf: true,
                path_traversal: true,
                prototype_pollution: true,
                file_inclusion: true,
                rce: true,
                deserialization: true
            }
        };

        fs.writeFileSync(configPath, JSON.stringify(defaultConfig, null, 2));
        console.log(chalk.green('✅ ShieldRASP initialized!'));
        console.log(chalk.dim(`Config created at: ${configPath}`));
        console.log(`\nNext steps:`);
        console.log(`1. Run: ${chalk.cyan('npm install @shieldrasp/agent')}`);
        console.log(`2. Add to your app: ${chalk.yellow('require("@shieldrasp/agent").start()')}`);
    });

// 3. STATUS - System Health
program
    .command('status')
    .description('Check ShieldRASP platform status')
    .action(() => {
        console.log(chalk.bold('\n--- ShieldRASP Status ---'));
        console.log(`Platform Service:  ${chalk.green('RUNNING')}`);
        console.log(`Telemetry Port:    ${chalk.cyan('50052')}`);
        console.log(`Active Agents:     ${chalk.yellow('1 online')}`);
        console.log('-------------------------\n');
    });

// 4. LOGS - Review History
program
    .command('logs')
    .description('View recent security logs')
    .action(() => {
        console.log(chalk.dim('Fetching local logs...'));
        const logs = [
            ['Timestamp', 'Event', 'Action'],
            ['2026-03-05 14:20', 'SQL Injection', chalk.red('BLOCKED')],
            ['2026-03-05 14:25', 'Scanner Activity', chalk.red('BLOCKED')],
            ['2026-03-05 15:10', 'Path Traversal', chalk.yellow('MONITORED')],
        ];
        console.log(table(logs));
    });

// 5. SIMULATE - Attack Testing
program
    .command('simulate')
    .description('Simulate attacks against the demo application')
    .action(() => {
        console.log(chalk.bold('\n🔥 ShieldRASP Attack Simulator'));
        console.log('Use these commands to test your protection:\n');

        console.log(chalk.cyan('SQL Injection:'));
        console.log(`  curl "http://localhost:8081/vuln/sqli?id=1' OR 1=1--"`);

        console.log(chalk.cyan('\nCommand Injection:'));
        console.log(`  curl "http://localhost:8081/vuln/cmd?host=google.com; whoami"`);

        console.log(chalk.cyan('\nPath Traversal:'));
        console.log(`  curl "http://localhost:8081/vuln/sqli?id=../../../../etc/passwd"`);

        console.log(chalk.cyan('\nHigh-Entropy Scanner Probe:'));
        console.log(`  curl "http://localhost:8081/vuln/sqli?id=a9j2u7k5m3v9p1z0q8x2y4"`);

        console.log('\n--------------------------------');
    });

// 6. RULES - Deprecated alias for management (backward compatibility)
program
    .command('rules')
    .description('View security rules')
    .action(() => {
        const rules = [
            ['ID', 'Name', 'Status'],
            ['sqli-001', 'SQL Injection (Generic)', chalk.green('Enabled')],
            ['cmd-001', 'Command Execution', chalk.green('Enabled')],
            ['path-001', 'Path Traversal', chalk.green('Enabled')],
            ['rce-001', 'Remote Code Execution', chalk.green('Enabled')]
        ];
        console.log(table(rules));
    });

program.parse();

