#!/bin/sh
set -e

ROOT="$(cd "$(dirname "$0")" && pwd)"
# shellcheck disable=SC1091
. "$ROOT/scripts/_load_env.sh"

KONG_STATUS_URL="${KONG_STATUS_URL:-}"
PROXY="${KONG_PROXY_URL:-http://127.0.0.1:8000}"
UI_PORT="${SIEM_UI_PORT:-3071}"
DOCKER_NETWORK="${DOCKER_NETWORK:-kong-net}"

if [ -z "${KONG_ADMIN_TOKEN}" ]; then
  echo "KONG_ADMIN_TOKEN is required. Copy .env.example to .env and set values." >&2
  exit 1
fi

if [ -n "${KONG_STATUS_URL}" ]; then
  if ! curl -sk "${KONG_STATUS_URL}" >/dev/null 2>&1; then
    echo "Kong is not ready at ${KONG_STATUS_URL}." >&2
    echo "Start Kong Gateway and set KONG_STATUS_URL / DECK_KONG_ADDR in .env." >&2
    exit 1
  fi
fi

if ! docker network inspect "${DOCKER_NETWORK}" >/dev/null 2>&1; then
  echo "Docker network '${DOCKER_NETWORK}' not found." >&2
  echo "Create it (or attach to your Kong stack network) and set DOCKER_NETWORK in .env." >&2
  echo "  docker network create ${DOCKER_NETWORK}" >&2
  exit 1
fi

chmod +x "$ROOT/scripts/"*.sh "$ROOT/start.sh" "$ROOT/stop.sh"

echo "=== SIEM detection demo start ==="
if ! docker compose -f "$ROOT/docker-compose.yml" up -d --wait; then
  echo "compose up failed; recreating containers..." >&2
  docker rm -f siem-demo-mock siem-demo-ui >/dev/null 2>&1 || true
  docker compose -f "$ROOT/docker-compose.yml" up -d --wait
fi

"$ROOT/scripts/deck-sync.sh"
"$ROOT/scripts/verify.sh"
"$ROOT/scripts/import-grafana-dashboard.sh" || true

GRAFANA_URL="${GRAFANA_URL:-http://127.0.0.1:3000}"

cat <<EOF

SIEM detection demo is ready.

  UI:         http://127.0.0.1:${UI_PORT}
  SIEM dash:  ${GRAFANA_URL}/d/kong-siem-detection
  Proxy:      ${PROXY}
  Routes:     /siem-demo/loan/customers/{id}
              /siem-demo/loan/open/info   (control gap)
              /siem-demo/heartbeat

EOF
