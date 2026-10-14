#!/bin/sh
# Shared env loader for scripts. Sourced, not executed.
ROOT="${ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"

if [ ! -f "$ROOT/.env" ] && [ -f "$ROOT/.env.example" ]; then
  cp "$ROOT/.env.example" "$ROOT/.env"
fi

if [ -f "$ROOT/.env" ]; then
  set -a
  # shellcheck disable=SC1091
  . "$ROOT/.env"
  set +a
fi

KONG_ADMIN_TOKEN="${KONG_ADMIN_TOKEN:-}"
DECK_KONG_ADDR="${DECK_KONG_ADDR:-http://127.0.0.1:8001}"
DEMO_WORKSPACE="${DEMO_WORKSPACE:-siem-demo}"
DECK_DEMO_TAG="${DECK_DEMO_TAG:-siem-demo}"
DOCKER_NETWORK="${DOCKER_NETWORK:-kong-net}"
