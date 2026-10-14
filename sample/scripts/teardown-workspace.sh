#!/bin/sh
set -e

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck disable=SC1091
. "$ROOT/scripts/_load_env.sh"

if [ -z "${KONG_ADMIN_TOKEN}" ]; then
  echo "KONG_ADMIN_TOKEN is required; skip teardown." >&2
  exit 0
fi

WORKSPACE="${DEMO_WORKSPACE}"
TAG="${DECK_DEMO_TAG}"

echo "Resetting decK tag '${TAG}' in workspace '${WORKSPACE}'..."
deck gateway reset \
  --kong-addr "${DECK_KONG_ADDR}" \
  --workspace "${WORKSPACE}" \
  --headers "Kong-Admin-Token: ${KONG_ADMIN_TOKEN}" \
  --select-tag "${TAG}" \
  --force || true

echo "teardown OK"
