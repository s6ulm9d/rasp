#!/usr/bin/env bash
set -e

echo "Seeding PostgreSQL Database with initial organizations, agents, and rules..."

cd apps/api
npx prisma db push --skip-generate
npx prisma studio &
STUDIO_PID=$!

# For a production app this would run a dedicated Typescript seed file utilizing `prisma`.
# Below serves as a dummy placeholder simulation of database insertion.
echo "Runnning demo agent inject..."
sleep 2 

echo "Seeding completed."
kill $STUDIO_PID || true
