#!/usr/bin/env node
import { Command } from 'commander';
import chalk from 'chalk';
import { Server } from 'socket.io';
import { table } from 'table';
const term = require('clui');

const program = new Command();

program
    .name('shieldrasp')
    .description('ShieldRASP CLI Tool for monitoring and security management')
    .version('1.0.0');

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
                const event = JSON.parse(data);
                console.log(chalk.red.bold(`\n!!! ATTACK DETECTED !!!`));
                const tableData = [
                    [chalk.bold('Field'), chalk.bold('Value')],
                    ['Type', chalk.yellow(event.attack_type)],
                    ['Subtype', event.attack_subtype],
                    ['Severity', event.severity === 'critical' ? chalk.red(event.severity) : chalk.yellow(event.severity)],
                    ['Payload', chalk.dim(event.payload)],
                    ['Blocked', event.blocked ? chalk.green('Yes') : chalk.red('No')],
                    ['Source IP', event.source_ip],
                    ['Path', event.http_path]
                ];
                console.log(table(tableData));
            });
        });
    });

program
    .command('rules')
    .description('Manage security rules')
    .action(() => {
        const rules = [
            ['ID', 'Name', 'Status'],
            ['sqli-001', 'SQL UNION Injection', chalk.green('Enabled')],
            ['cmd-001', 'Command Injection', chalk.green('Enabled')],
            ['path-001', 'Path Traversal', chalk.green('Enabled')],
            ['proto-001', 'Prototype Pollution', chalk.red('Disabled')]
        ];
        console.log(table(rules));
    });

program
    .command('agents')
    .description('List connected RASP agents')
    .action(() => {
        console.log(chalk.cyan('Connected Agents:'));
        console.log(' - node-service-A (production)\n - python-backend-B (staging)');
    });

program.parse();
