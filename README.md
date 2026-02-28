# ShieldRASP Monorepo
A Runtime Application Self-Protection tool that runs inside Node.js, Python, and Java applications. 
It detects and blocks injection attacks, command execution, path traversal, SSRF, deserialization attacks, prototype pollution, and behavioral anomalies in real-time.

## Features
* **Fail-open architecture:** Agents will never crash the host application.
* **Taint Engine Tracking:** Memory-based lightweight variable taint tracking across languages.
* **Real-time API & Dashboard:** View unified threats via the gRPC Ingestor + WebSocket streaming API.
* **ML Inference Anomaly Tracking:** Isolation Forest based behavioral attack detection on request patterns. 

## Requirements
* Docker & Docker Compose
* Node.js v20+
* Python 3.11+
* Go 1.22+
* Java 11+

## Quick Start (under 5 minutes)

1. **Setup Environment**:
   ```bash
   chmod +x scripts/setup.sh
   ./scripts/setup.sh
   ```

2. **Generate Local TLS Certs**:
   ```bash
   chmod +x scripts/generate-certs.sh
   ./scripts/generate-certs.sh
   ```

3. **Spin up Core Infrastructure** (Postgres, Redis, Kafka):
   ```bash
   docker compose up -d postgres redis zookeeper kafka
   ```

4. **Seed the Database** (Default dummy agents & rules):
   ```bash
   chmod +x scripts/seed.sh
   ./scripts/seed.sh
   ```

5. **Run all Apps** (API, Dashboard, ML, Ingestor, Demo App):
   If building locally via turborepo:
   ```bash
   npm run dev
   ```
   Or to run everything via containers:
   ```bash
   docker compose up -d
   ```

## Folder Structure
* `apps/`
  * `api` - NestJS Control Plane and Websockets
  * `dashboard` - Next.js 14 React UI
  * `ingestor` - Go High-throughput gRPC service
  * `ml-inference` - Python Anomaly Detection Scorer
  * `demo-app` - Vulnerable Express server to test agents
* `packages/`
  * `agent-node` - Typescript Node.js RASP
  * `agent-python` - Python 3 RASP
  * `agent-java` - Java JVM Class Transformer RASP
  * `proto` - gRPC Definitions
  * `detection-rules` - AST and Regex vulnerability logic
