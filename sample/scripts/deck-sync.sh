#!/bin/sh
set -e

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck disable=SC1091
. "$ROOT/scripts/_load_env.sh"

if [ -z "${KONG_ADMIN_TOKEN}" ]; then
  echo "KONG_ADMIN_TOKEN is required (set in .env)." >&2
  exit 1
fi

TAG="${DECK_DEMO_TAG}"
WORKSPACE="${DEMO_WORKSPACE}"

"$ROOT/scripts/setup-workspace.sh"

echo "Validating decK (tag: ${TAG}, workspace: ${WORKSPACE})..."
deck gateway validate "$ROOT/deck/siem-demo.yaml" \
  --kong-addr "${DECK_KONG_ADDR}" \
  --workspace "${WORKSPACE}" \
  --headers "Kong-Admin-Token: ${KONG_ADMIN_TOKEN}"

echo "Syncing decK tag '${TAG}' into workspace '${WORKSPACE}'..."
deck gateway sync "$ROOT/deck/siem-demo.yaml" \
  --kong-addr "${DECK_KONG_ADDR}" \
  --workspace "${WORKSPACE}" \
  --headers "Kong-Admin-Token: ${KONG_ADMIN_TOKEN}" \
  --select-tag "${TAG}" \
  --parallelism 1

echo "Waiting for Admin route siem-demo-customers-route..."
elapsed=0
code="000"
while [ "${elapsed}" -lt 60 ]; do
  code=$(curl -sS -o /dev/null -w "%{http_code}" \
    -H "Kong-Admin-Token: ${KONG_ADMIN_TOKEN}" \
    "${DECK_KONG_ADDR}/${WORKSPACE}/routes/siem-demo-customers-route" || echo "000")
  if [ "$code" = "200" ]; then
    echo "Admin route ready. Waiting 4s for DP config..."
    sleep 4
    break
  fi
  sleep 2
  elapsed=$((elapsed + 2))
done
if [ "$code" != "200" ]; then
  echo "Timed out waiting for Admin route (last HTTP ${code})." >&2
  exit 1
fi

echo "deck-sync OK"
