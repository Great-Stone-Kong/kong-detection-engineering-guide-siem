#!/bin/sh
set -e

ROOT="$(cd "$(dirname "$0")" && pwd)"

if [ -f "$ROOT/.env" ]; then
  set -a
  # shellcheck disable=SC1091
  . "$ROOT/.env"
  set +a
fi

echo "=== SIEM detection demo 202610 stop ==="
"$ROOT/scripts/teardown-workspace.sh" || true
docker compose -f "$ROOT/docker-compose.yml" down --remove-orphans
echo "SIEM detection demo stopped."
