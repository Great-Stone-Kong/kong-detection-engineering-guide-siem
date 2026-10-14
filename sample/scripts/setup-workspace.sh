#!/bin/sh
set -e

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck disable=SC1091
. "$ROOT/scripts/_load_env.sh"

if [ -z "${KONG_ADMIN_TOKEN}" ]; then
  echo "KONG_ADMIN_TOKEN is required (set in .env)." >&2
  exit 1
fi

WORKSPACE="${DEMO_WORKSPACE}"

status="$(curl -sS -o /dev/null -w "%{http_code}" \
  -H "Kong-Admin-Token: ${KONG_ADMIN_TOKEN}" \
  "${DECK_KONG_ADDR}/workspaces/${WORKSPACE}" || true)"

if [ "$status" = "200" ]; then
  echo "Workspace '${WORKSPACE}' already exists."
  exit 0
fi

echo "Creating workspace '${WORKSPACE}'..."
code="$(curl -sS -o /tmp/siem-demo-ws.json -w "%{http_code}" \
  -X POST "${DECK_KONG_ADDR}/workspaces" \
  -H "Kong-Admin-Token: ${KONG_ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{\"name\":\"${WORKSPACE}\",\"comment\":\"Kong SIEM detection engineering demo\"}")"

if [ "$code" = "201" ] || [ "$code" = "200" ] || [ "$code" = "409" ]; then
  echo "Workspace '${WORKSPACE}' created."
  exit 0
fi

echo "Failed to create workspace (${code}):" >&2
cat /tmp/siem-demo-ws.json >&2
exit 1
