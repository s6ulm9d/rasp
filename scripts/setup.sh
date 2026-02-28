#!/usr/bin/env bash
set -e

echo "Setting up ShieldRASP Local Dev Environment..."

# Install root dependencies and turbo
npm install

# Setup API
cd apps/api
npm install
npx prisma generate
cd ../..

# Setup Dashboard
cd apps/dashboard
npm install
cd ../..

echo "Setup complete! Run 'docker compose up' to start the infrastructure, then 'npm run dev' to start the apps."
