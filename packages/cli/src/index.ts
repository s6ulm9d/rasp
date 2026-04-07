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
    .description('ShieldRASP CLI Management Tool')
    .version('1.0.0');

// 1. MONITOR - Live Telemetry
program
    .command('monitor')
    .description('Start real-time attack monitor')
    .option('-p, --port <number>', 'Telemetry port', '50052')
    .action((options) => {
        const io = new Server(parseInt(options.port), {
            cors: {
                origin: "*",
                methods: ["GET", "POST"]
            }
        });
        console.log(chalk.green(`🚀 ShieldRASP CLI Monitor started on port ${options.port}`));
        console.log(chalk.dim('Awaiting telemetry streams from agents...'));

        io.on('connection', (socket) => {
            console.log(chalk.blue(`[CONNECTED] Agent connected: ${socket.id}`));

            socket.on('telemetry', (data) => {
                const event = typeof data === 'string' ? JSON.parse(data) : data;
                console.log(chalk.red.bold(`\n!!! ATTACK DETECTED !!!`));
                const tableData = [
                    [chalk.bold('Field'), chalk.bold('Value')],
                    ['Req ID', chalk.blueBright(event.requestId || 'N/A')],
                    ['Score', (event.score && event.score >= 80) ? chalk.bgRed.white(` ${event.score} `) : chalk.yellow(event.score || 'N/A')],
                    ['Type', chalk.yellow(event.attack)],
                    ['Payload', chalk.dim(event.payload ? event.payload.substring(0, 100) : '')],
                    ['Action', event.action === 'blocked' ? chalk.bgRed.white(' BLOCKED ') : chalk.yellow(' LOGGED ')],
                    ['Chain', chalk.cyan(event.chain ? event.chain.length + ' rules triggered' : 'N/A')],
                    ['Path', event.path || '/']
                ];
                console.log(table(tableData));
            });
        });
    });

import { runInitCommand } from './commands/init';

// 2. INIT - Project Initialization
program
    .command('init')
    .description('Initialize ShieldRASP configuration safely into the current codebase')
    .action(() => {
        runInitCommand();
    });

// 3. STATUS - System Health
program
    .command('status')
    .description('Show platform status')
    .action(() => {
        console.log(chalk.bold('\n--- ShieldRASP Status ---'));
        console.log(`Agent Connection: ${chalk.green('Online')}`);
        console.log(`Config:           ${chalk.cyan('Found (~/.shieldrasp/shieldrasp.json)')}`);
        console.log(`Monitor Mode:     ${chalk.yellow('Active on port 50052')}\n`);
    });

// 4. SIMULATE - Attack Testing
program
    .command('simulate')
    .description('Show example attack payloads for testing')
    .action(() => {
        console.log(chalk.bold('\n🔥 ShieldRASP Attack Simulator'));
        console.log('Copy/paste these commands to test your protection:\n');

        console.log(chalk.cyan('SQL Injection:'));
        console.log(`  curl "http://localhost:8081/vuln/sqli?id=1' OR 1=1--"`);

        console.log(chalk.cyan('\nCommand Injection:'));
        console.log(`  curl "http://localhost:8081/vuln/cmd?host=google.com;whoami"`);

        console.log(chalk.cyan('\nPath Traversal:'));
        console.log(`  curl "http://localhost:8081/vuln/path?file=../../../../etc/passwd"`);

        console.log(chalk.cyan('\nRemote Code Execution (RCE):'));
        console.log(`  curl "http://localhost:8081/vuln/rce?code=process.exit(1)"`);

        console.log(chalk.cyan('\nPrototype Pollution:'));
        console.log(`  curl -X POST -H "Content-Type: application/json" -d '{"__proto__":{"polluted":true}}' http://localhost:8081/vuln/prototype`);

        console.log(chalk.cyan('\nSSRF (Internal Probe):'));
        console.log(`  curl "http://localhost:8081/vuln/ssrf?url=http://169.254.169.254/latest/meta-data/"`);

        console.log('\n----------------------------------');
    });

program.parse();
