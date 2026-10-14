#!/bin/sh
set -e

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck disable=SC1091
. "$ROOT/scripts/_load_env.sh"

GRAFANA_URL="${GRAFANA_URL:-http://127.0.0.1:3000}"
GRAFANA_ADMIN_USER="${GRAFANA_ADMIN_USER:-admin}"
GRAFANA_ADMIN_PASSWORD="${GRAFANA_ADMIN_PASSWORD:-}"
DASH_JSON="$ROOT/grafana/siem-detection.json"
GEN="$ROOT/grafana/generate_dashboard.py"

if [ -f "$GEN" ]; then
  python3 "$GEN"
fi

if [ ! -f "$DASH_JSON" ]; then
  echo "Dashboard file missing: $DASH_JSON" >&2
  exit 1
fi

if [ -z "${GRAFANA_ADMIN_PASSWORD}" ]; then
  echo "GRAFANA_ADMIN_PASSWORD unset; skip dashboard import." >&2
  exit 0
fi

if ! curl -sf -u "${GRAFANA_ADMIN_USER}:${GRAFANA_ADMIN_PASSWORD}" \
  "${GRAFANA_URL}/api/health" >/dev/null 2>&1; then
  echo "Grafana not ready at ${GRAFANA_URL}; skip dashboard import." >&2
  exit 0
fi

folder_uid="siem"
folder_code=$(curl -sS -o /tmp/gf-folder.json -w "%{http_code}" \
  -u "${GRAFANA_ADMIN_USER}:${GRAFANA_ADMIN_PASSWORD}" \
  -H "Content-Type: application/json" \
  -X POST "${GRAFANA_URL}/api/folders" \
  -d "{\"uid\":\"${folder_uid}\",\"title\":\"SIEM\"}" || echo "000")
if [ "$folder_code" != "200" ] && [ "$folder_code" != "409" ]; then
  curl -sS -u "${GRAFANA_ADMIN_USER}:${GRAFANA_ADMIN_PASSWORD}" \
    "${GRAFANA_URL}/api/folders/${folder_uid}" >/tmp/gf-folder.json || true
fi

payload=$(python3 - <<PY
import json
dash = json.load(open("${DASH_JSON}"))
dash["id"] = None
body = {
  "dashboard": dash,
  "folderUid": "${folder_uid}",
  "overwrite": True,
  "message": "siem-engineering import",
}
print(json.dumps(body))
PY
)

code=$(curl -sS -o /tmp/gf-import.json -w "%{http_code}" \
  -u "${GRAFANA_ADMIN_USER}:${GRAFANA_ADMIN_PASSWORD}" \
  -H "Content-Type: application/json" \
  -X POST "${GRAFANA_URL}/api/dashboards/db" \
  -d "$payload")

if [ "$code" != "200" ]; then
  echo "Grafana dashboard import failed (HTTP ${code}):" >&2
  cat /tmp/gf-import.json >&2
  exit 1
fi

url=$(python3 -c "import json; print(json.load(open('/tmp/gf-import.json')).get('url',''))")
echo "Grafana dashboard imported: ${GRAFANA_URL}${url}"
echo "Direct: ${GRAFANA_URL}/d/kong-siem-detection"
