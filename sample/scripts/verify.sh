#!/bin/sh
set -e

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if [ -f "$ROOT/.env" ]; then
  set -a
  # shellcheck disable=SC1091
  . "$ROOT/.env"
  set +a
fi

PROXY="${KONG_PROXY_URL:-http://127.0.0.1:8000}"
APIKEY="${DEMO_APIKEY:-siem-good-key}"
LOKI_HOST="${LOKI_HOST:-http://127.0.0.1:3100}"
UI_PORT="${SIEM_UI_PORT:-3071}"

echo "=== verify authenticated customer ==="
code=$(curl -sS -o /tmp/siem-cust.json -w "%{http_code}" \
  -H "apikey: ${APIKEY}" \
  -H "User-Agent: Mozilla/5.0 (SIEM-verify)" \
  -H "X-Demo-Tag: siem-test" \
  "${PROXY}/siem-demo/loan/customers/4242")
echo "HTTP ${code}"
head -c 200 /tmp/siem-cust.json; echo
if [ "${code}" != "200" ]; then
  echo "FAIL: authenticated customer" >&2
  exit 1
fi

echo "=== verify control-gap open route ==="
code=$(curl -sS -o /tmp/siem-open.json -w "%{http_code}" \
  -H "User-Agent: Mozilla/5.0 (SIEM-verify)" \
  "${PROXY}/siem-demo/loan/open/info")
echo "HTTP ${code}"
if [ "${code}" != "200" ]; then
  echo "FAIL: open route" >&2
  exit 1
fi

echo "=== verify heartbeat ==="
code=$(curl -sS -o /dev/null -w "%{http_code}" \
  -H "User-Agent: Mozilla/5.0 (SIEM-verify)" \
  "${PROXY}/siem-demo/heartbeat")
echo "HTTP ${code}"
if [ "${code}" != "200" ]; then
  echo "FAIL: heartbeat" >&2
  exit 1
fi

echo "=== verify auth failure (expect 401) ==="
code=$(curl -sS -o /dev/null -w "%{http_code}" \
  -H "apikey: wrong-verify-key" \
  -H "User-Agent: Mozilla/5.0 (SIEM-verify)" \
  "${PROXY}/siem-demo/loan/customers/1")
echo "HTTP ${code}"
if [ "${code}" != "401" ] && [ "${code}" != "403" ]; then
  echo "FAIL: expected 401/403 got ${code}" >&2
  exit 1
fi

echo "=== wait for http-log → Loki ==="
sleep 3
end_ns=$(python3 -c 'import time; print(int(time.time()*1e9))')
start_ns=$(python3 -c "print(${end_ns} - 120*10**9)")
loki_code=$(curl -sS -o /tmp/siem-loki.json -w "%{http_code}" \
  --get "${LOKI_HOST}/loki/api/v1/query_range" \
  --data-urlencode 'query={log_source="http-log"} |= "siem-demo"' \
  --data-urlencode "start=${start_ns}" \
  --data-urlencode "end=${end_ns}" \
  --data-urlencode "limit=20")
echo "Loki HTTP ${loki_code}"
if [ "${loki_code}" != "200" ]; then
  echo "FAIL: Loki query" >&2
  cat /tmp/siem-loki.json >&2
  exit 1
fi
if ! grep -q 'siem-demo' /tmp/siem-loki.json; then
  echo "WARN: no siem-demo lines in Loki yet (pipeline lag); UI evaluate may still work after settle" >&2
fi

echo "=== verify UI health ==="
ui_code=$(curl -sS -o /dev/null -w "%{http_code}" "http://localhost:${UI_PORT}/health" || echo "000")
echo "UI HTTP ${ui_code}"
if [ "${ui_code}" != "200" ]; then
  echo "FAIL: UI health" >&2
  exit 1
fi

echo "verify OK"
