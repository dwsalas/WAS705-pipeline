#!/usr/bin/env bash
# Scripted secure (re)deployment of the hardened Firefly III stack.
# Run from the deploy/ directory on the TARGET machine.
set -euo pipefail
cd "$(dirname "$0")"

[ -f .env ] || { echo "ERROR: .env missing (copy .env.hardened.example -> .env and fill it in)"; exit 1; }
[ -f patch/ExportDataGenerator.php ] || { echo "ERROR: patched exporter missing; run apply_csv_patch.sh first"; exit 1; }

echo "== Bringing up hardened stack =="
docker compose -f docker-compose.hardened.yml up -d --remove-orphans

echo "== Waiting for HTTPS to answer =="
for i in $(seq 1 30); do
  code=$(curl -sk -o /dev/null -w "%{http_code}" https://localhost/login || true)
  echo "  attempt $i -> $code"
  [ "$code" = "200" ] || [ "$code" = "302" ] && { echo "Up."; exit 0; }
  sleep 5
done
echo "WARNING: stack did not report healthy in time; check 'docker compose logs'."
