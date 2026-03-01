#!/usr/bin/env bash
set -e

echo "🛡️ Setting up ShieldRASP Monorepo (CLI Edition)..."

# Install root dependencies
npm install

# Build the CLI
echo "🛠️ Building ShieldRASP CLI..."
npm run build --workspace=@shieldrasp/cli

# Build the Node Agent
echo "🛠️ Building ShieldRASP Node Agent..."
npm run build --workspace=@shieldrasp/node-agent

# Setup Demo App
echo "📦 Setting up Demo App..."
cd apps/demo-app
npm install
cd ../..

echo "✅ Setup complete! You can now start the monitor and follow the README instructions."
