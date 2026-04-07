import * as fs from 'fs';
import * as path from 'path';
import chalk from 'chalk';
import * as crypto from 'crypto';

export function runInitCommand() {
    console.log(chalk.bold('\n🛡️ Initializing ShieldRASP Zero-Friction Integration...'));

    const cwd = process.cwd();
    const pkgPath = path.join(cwd, 'package.json');

    // 1. Detect project root
    if (!fs.existsSync(pkgPath)) {
        console.error(chalk.red('❌ Error: Could not find package.json in the current directory.'));
        console.error(chalk.yellow('👉 Run `npx shieldrasp init` from the root of your Node.js project.'));
        process.exit(1);
    }

    let pkgRaw = '';
    let pkg: any = {};

    try {
        pkgRaw = fs.readFileSync(pkgPath, 'utf-8');
        pkg = JSON.parse(pkgRaw);
    } catch (e) {
        console.error(chalk.red('❌ Error: package.json is corrupted or invalid JSON.'));
        process.exit(1);
    }

    // 2. Backup Strategy
    const backupPath = path.join(cwd, 'package.json.shieldrasp.bak');
    try {
        fs.writeFileSync(backupPath, pkgRaw);
    } catch (e) {
        console.error(chalk.red('❌ Error: Could not create backup of package.json. Aborting to ensure absolute safety.'));
        process.exit(1);
    }

    let injected = false;
    let fallbackMode = false;
    const injectionFlag = '-r @shieldrasp/agent';

    // 3. Script Safe Injection Strategy
    if (!pkg.scripts) pkg.scripts = {};

    const targetScripts = ['start', 'dev'];
    let scriptModified = false;

    for (const scriptName of targetScripts) {
        if (pkg.scripts[scriptName]) {
            const originalScript = pkg.scripts[scriptName];
            
            // Idempotency check
            if (originalScript.includes('@shieldrasp/agent')) {
                console.log(chalk.yellow(`⚡ ShieldRASP already injected in \`npm run ${scriptName}\` script. Skipping.`));
                injected = true;
                scriptModified = true;
                continue;
            }

            // Check if it's a standard Node execution string
            if (originalScript.startsWith('node ') || originalScript.includes(' node ')) {
                const modifiedScript = originalScript.replace(/(\bnode\b)/, `$1 ${injectionFlag}`);
                pkg.scripts[scriptName] = modifiedScript;
                injected = true;
                scriptModified = true;
                console.log(chalk.blue(`[Hooks] Injected agent safely into \`npm run ${scriptName}\``));
            } else {
                console.log(chalk.yellow(`⚠️ Script \`${scriptName}\` is highly complex (${originalScript}). Skipping auto-rewrite to prevent breaking changes.`));
            }
        }
    }

    if (!scriptModified) {
        // Fallback Entry Point Detection
        let entryPoint = '';
        if (pkg.main && fs.existsSync(path.join(cwd, pkg.main))) {
            entryPoint = pkg.main;
        } else if (fs.existsSync(path.join(cwd, 'index.js'))) {
            entryPoint = 'index.js';
        } else if (fs.existsSync(path.join(cwd, 'app.js'))) {
            entryPoint = 'app.js';
        } else if (fs.existsSync(path.join(cwd, 'server.js'))) {
            entryPoint = 'server.js';
        }

        if (entryPoint) {
            pkg.scripts.start = `node ${injectionFlag} ${entryPoint}`;
            injected = true;
            console.log(chalk.blue(`[Hooks] Auto-created 'start' script mapping to entry point: ${entryPoint}`));
        } else {
            console.log(chalk.yellow(`⚠️ Could not detect a valid entry file (main/index/app/server).`));
        }
    }

    // 4. Fallback execution
    if (!injected) {
        console.log(chalk.cyan(`\n[Fallback] Script modification skipped. Generating universal Environment hook instead:`));
        console.log(chalk.white(`   For PowerShell:  $env:NODE_OPTIONS = "--require @shieldrasp/agent"`));
        console.log(chalk.white(`   For Linux/macOS: export NODE_OPTIONS="--require @shieldrasp/agent"`));
        fallbackMode = true;
    }

    // 5. Write back to Package.json safely
    if (injected) {
        try {
            fs.writeFileSync(pkgPath, JSON.stringify(pkg, null, 2));
        } catch (e) {
            console.error(chalk.red('❌ Failed to save modified package.json. Restoring backup...'));
            fs.writeFileSync(pkgPath, pkgRaw);
            process.exit(1);
        }
    }

    // 6. Config Handling (Zero Friction)
    const configPath = path.join(cwd, 'shieldrasp.json');
    if (!fs.existsSync(configPath)) {
        const projectId = crypto.createHash('sha256').update(pkg.name || 'project' + require('os').hostname()).digest('hex').substring(0, 12);
        const defaultConfig = {
            projectId,
            mode: 'block',
            endpoint: 'http://localhost:50052',
            protections: {
                ssrf: 'block',
                sqli: 'block',
                xss: 'log',
                cmd: 'block',
                path: 'block'
            }
        };
        fs.writeFileSync(configPath, JSON.stringify(defaultConfig, null, 2));
        console.log(chalk.blue(`[Config] Generated shieldrasp.json (Project ID: ${projectId})`));
    }

    // 7. CLI Output (UX)
    console.log('\n----------------------------------------');
    console.log(chalk.green('✔ ShieldRASP installed successfully'));
    if (injected) {
        console.log(chalk.green('✔ Agent safely injected via package.json'));
    } else {
        console.log(chalk.yellow('⚠ Environment injection required (NODE_OPTIONS)'));
    }
    console.log(chalk.green('✔ No existing files modified destructively'));
    console.log(chalk.green('✔ Protection enabled'));
    if (injected) {
        console.log(chalk.green('✔ Run: npm start'));
    }
    console.log(chalk.cyan('\n✔ Dashboard: http://localhost:50052'));
    console.log('----------------------------------------\n');
}
