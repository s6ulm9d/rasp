# ShieldRASP Monorepo (CLI Edition)
A Runtime Application Self-Protection tool that runs inside Node.js, Python, and Java applications.
This version has been converted from a web-application into a dedicated **CLI Tool** for terminal-based security management.

## Features
* **Zero-config Monitoring:** Run `shieldrasp monitor` to start a local listener.
* **Terminal Dashboard:** Real-time attack visualization directly in your terminal.
* **Taint Engine Tracking:** Memory-based lightweight variable taint tracking across languages.
* **Rule Management:** Toggle security rules via CLI commands.

## Requirements
* Node.js v20+
* Python 3.11+
* Java 11+

## Quick Start

1. **Install Dependencies**:
   ```bash
   npm install
   ```

2. **Build the CLI**:
   ```bash
   npm run build --workspace=@shieldrasp/cli
   ```

3. **Start the Monitor**:
   ```bash
   # From the project root
   npm run cli -- monitor
   ```

4. **Run the Demo App**:
   ```bash
   # In another terminal
   cd apps/demo-app
   npm start
   ```

## CLI Commands
* `shieldrasp monitor` - Starts the telemetry collector.
* `shieldrasp rules` - Lists and manages protection rules.
* `shieldrasp agents` - Shows status of connected RASP agents.

## Folder Structure
* `packages/`
  * `cli` - The main ShieldRASP control interface.
  * `agent-node` - Typescript Node.js RASP.
  * `agent-python` - Python 3 RASP.
  * `agent-java` - Java JVM Class Transformer RASP.
  * `proto` - gRPC Definitions.
  * `detection-rules` - AST and Regex vulnerability logic.
