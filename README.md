# Kong SIEM Detection Engineering Guide

Detection criteria: **DETECTION ENGINEERING 2026**  
한국어: [README_KO.md](./README_KO.md)

Design and validate Kong Gateway API detection rules for SIEM. This repository ships reusable artifacts (decK, LogQL thresholds, Grafana dashboard, replay UI). It does **not** bundle Kong CP/DP, Loki, or Grafana—attach to your existing Gateway and log pipeline.

---

## Repository layout

```text
.
├── README.md / README_KO.md   # documentation
└── sample/                    # runnable demo artifacts
    ├── deck/siem-demo.yaml    # Kong entities (select-tag: siem-demo)
    ├── logql/rules.yaml       # per-rule demo thresholds / LogQL
    ├── grafana/               # SIEM dashboard JSON
    ├── mock/                  # upstream mock
    ├── ui/                    # attack replay / evaluate UI
    ├── scripts/               # workspace, decK, verify, Grafana import
    ├── images/                # dashboard screenshots
    ├── docker-compose.yml     # mock + UI only
    ├── start.sh / stop.sh
    └── .env.example
```

---

## Prerequisites

| Item | Requirement |
|------|-------------|
| Kong Gateway | Enterprise (Admin API + Proxy). Admin Token if RBAC is on |
| Log pipeline | `http-log` → collector (e.g. Fluent Bit) → SIEM store (e.g. Loki) |
| Tools | `deck`, `curl`, Docker (for mock/UI), optional Grafana |
| Network | Docker network where mock/UI can reach Kong DP and Loki |

Copy `sample/.env.example` to `sample/.env` and set endpoints for your environment.

| Variable | Meaning |
|----------|---------|
| `DECK_KONG_ADDR` | Kong Admin API |
| `KONG_ADMIN_TOKEN` | Admin Token |
| `KONG_PROXY_URL` | Proxy (host-side curl) |
| `KONG_STATUS_URL` | Gateway readiness URL |
| `KONG_PROXY_INTERNAL` / `KONG_ADMIN_INTERNAL` | UI container → Kong |
| `DOCKER_NETWORK` | External Docker network name for mock/UI |
| `LOKI_URL` | UI → Loki |
| `GRAFANA_URL` | Grafana base URL |
| `DEMO_WORKSPACE` / `DECK_DEMO_TAG` | defaults: `siem-demo` |

---

## Quick start

```bash
cd sample
cp .env.example .env
# edit .env for your Admin / Proxy / Loki / Grafana / network

docker network create "${DOCKER_NETWORK:-kong-net}" 2>/dev/null || true

./start.sh
./stop.sh
```

| Item | Default |
|------|---------|
| Demo UI | `http://127.0.0.1:${SIEM_UI_PORT:-3071}` |
| Workspace | `siem-demo` |
| Consumer key | `siem-good-key` |
| SIEM dashboard | `${GRAFANA_URL}/d/kong-siem-detection` |

decK only:

```bash
cd sample && ./scripts/deck-sync.sh
```

---

## Purpose

Detect on Kong API traffic:

- Auth failure bursts and fail-then-success
- Authorization bypass signals (BOLA / ID enumeration)
- Rate-limit abuse, bots, URI attack signatures
- Mass successful reads / exfiltration
- Control-plane gaps and telemetry silence

Rule cards follow DETECTION ENGINEERING 2026 **WHEN / GROUP·RELATE BY / WITHIN / THEN**.  
LogQL below is a **Loki example**; map the same logic to your SIEM.

---

## Architecture

```text
Client / validation traffic
      │
      ▼
Kong DP  ── http-log JSON ──► Fluent Bit ──► Loki (example SIEM store)
      │                                        │
      ▼                                        ▼
Upstream API                         Grafana SIEM dashboard
```

Workspace note: a global `http-log` in `default` does **not** cover other workspaces. Put workspace-scoped `http-log` on the workspace that owns the sensitive APIs.

---

## Telemetry (http-log fields)

| SIEM field | Kong path | Use |
|------------|-----------|-----|
| `src_ip` | `client_ip` | source / geo |
| `http.path` | `request.uri` | path / ID tampering |
| `http.status` | `response.status` | 401/403/429/200 |
| `bytes_out` | `response.size` | mass response |
| `consumer` | `consumer.username` | identity aggregations |
| `ua` | `request.headers.user-agent` | bot / script |
| `route` | `route.name` | asset scope |

Prefer the body `consumer` object over `x-consumer-*` headers.

Recommended plugins: `http-log`, auth (`key-auth` / OIDC / JWT), `acl`, `rate-limiting-advanced`, `bot-detection`, optional `ip-restriction` / `request-validator` / `prometheus`.

---

## Operating model (DETECTION ENGINEERING 2026)

| Element | Kong mapping |
|---------|----------------|
| **WHEN** | status, path, bytes, UA, rate-limit headers |
| **GROUP / RELATE BY** | `consumer`, `client_ip`, `route.name` |
| **WITHIN** | 5m / 15m / 1h after baseline |
| **THEN** | severity, ticket, consumer limit, IP block |

Response types: **A** account/session · **F** web/vuln · **I** data exfil · **J** detection health · **C** attack chain.

Safety validation expects: telemetry present, single match, enrichments filled, analyst timeline possible, test tag present.

---

## Attack stage → KG-API map

| Stage | Threat | DE-like pattern | Rule |
|-------|--------|-----------------|------|
| Auth burst | key/token stuffing | DE-001 | KG-API-001 |
| Fail then success | 401s then 200 | DE-002 | KG-API-001b |
| Authz flaw | BOLA / ID walk | DE-071 (path IDs) | KG-API-002 |
| Automation | script UA / 429 | web abuse + DE-071 | KG-API-003, 004, 008 |
| Exfil | mass 200 / bytes | DE-071, DE-073 | KG-API-005 |
| Control gap | no auth/RLA on sensitive route | DE-088 | KG-API-006 |
| Log silence | http-log EPS=0 | DE-091 | KG-API-009 |
| Chain | stuffing then mass read | DE-002 + DE-071/073 | KG-API-007 |

---

## Rule cards (summary + LogQL)

Production windows/thresholds come from baseline. Values below are **validation** examples (short windows). Full WHEN/THEN tables: see [README_KO.md](./README_KO.md) (same IDs).

| ID | Intent | Signal | Response | Demo threshold |
|----|--------|--------|----------|----------------|
| 001 | Auth failure burst | 401/403 count by IP/route | A | ≥10 / 2m |
| 001b | Fail then success | fails then 200 same route | A | ≥3 fails then 200 / 3m |
| 002 | BOLA ID enum | distinct path IDs + 200 | F | ≥12 IDs / 2m |
| 003 | Rate limit | 429 | F | ≥1 / 2m |
| 004 | Script UA | python-requests/curl + sensitive route | F | UA match / 2m |
| 005 | Mass exfil | 200 count or `sum(response.size)` | I+A | ≥5 or ≥400KB / 3m |
| 006 | Control gap | Admin/decK missing auth or RLA | F | config scan |
| 007 | Chain | 001 then 005 | C+A+I | within 5m |
| 008 | URI signature | `../`, `%2e%2e` | F | pattern / 2m |
| 009 | Telemetry silence | heartbeat EPS=0, proxy up | J | 0 / 2m |

### Example LogQL

```logql
# KG-API-001
sum by (client_ip) (
  count_over_time(
    {log_source="http-log"}
    | json
    | route_name = "siem-demo-customers-route"
    | response_status = "401" or response_status = "403"
    | __error__ = ""
    [2m]
  )
)

# KG-API-003
sum(count_over_time(
  {log_source="http-log"} |= `/loan/customers`
  | json | response_status = "429" [2m]
))

# KG-API-008
sum(count_over_time(
  {log_source="http-log"} |= `/siem-demo/`
  |~ `(?i)(\.\./|%2e%2e|\.\.%2f)` [2m]
))

# KG-API-009
sum(count_over_time(
  {log_source="http-log"} |= `/siem-demo/heartbeat` [2m]
))
```

Pseudo-logic for 001:

```text
WHEN count(status IN {401,403}) BY client_ip, route.name
WITHIN 5m
THRESHOLD >= baseline * 3 OR >= 50
THEN alert high "kong_auth_failure_burst"
```

---

## decK example

File: `sample/deck/siem-demo.yaml` (tag `siem-demo`). Sync with `--select-tag siem-demo` only.

| Path | Plugins | Rules |
|------|---------|-------|
| workspace global | `http-log` → collector | all |
| `/siem-demo/loan/customers` | key-auth, acl, RLA, bot-detection | 001–005, 007, 008 |
| `/siem-demo/loan/open` | none (intentional gap) | 006 |
| `/siem-demo/heartbeat` | none | 009 |

```bash
deck gateway sync sample/deck/siem-demo.yaml \
  --kong-addr "${DECK_KONG_ADDR}" \
  --workspace "${DEMO_WORKSPACE:-siem-demo}" \
  --headers "Kong-Admin-Token: ${KONG_ADMIN_TOKEN}" \
  --select-tag siem-demo \
  --parallelism 1
```

Smoke:

```bash
curl -sS -H 'apikey: siem-good-key' \
  "${KONG_PROXY_URL}/siem-demo/loan/customers/1001"

for i in $(seq 1 12); do
  curl -sS -o /dev/null -w "%{http_code}\n" \
    -H "apikey: bad-$i" \
    "${KONG_PROXY_URL}/siem-demo/loan/customers/x"
done
```

Set `http-log.config.http_endpoint` to your collector URL. Change mock upstream URL to a real service in production.

---

## Loki labels (example)

| Label | Example | Use |
|-------|---------|-----|
| `job` | `kong-dp` | plane |
| `log_source` | `http-log` | plugin source filter |

Thresholds used by the UI live in `sample/logql/rules.yaml`.

---

## Grafana dashboard

- UID: `kong-siem-detection`
- Datasource: Loki (`uid: loki`)
- Import: `sample/scripts/import-grafana-dashboard.sh` (also from `sample/start.sh`)

| Section | Panels |
|---------|--------|
| Overview | risk score 0–100, KPIs, status trends, geomap, top attackers, logs |
| Scenarios | KG-API-001–009 blocks |

Risk score caps: 401/403 (+1, max 40) · 429 (+2, max 20) · script UA (+5, max 20) · URI (+10, max 20).  
Bands: 0–19 normal · 20–39 watch · 40–59 caution · 60–79 elevated · 80–100 critical.

Overview (risk score · KPIs), HTTP status trends, threat map, and recent logs:

![Kong SIEM Detection dashboard](./sample/images/screenshot.png)

---

## Investigation order

1. Telemetry healthy (KG-API-009)  
2. Primary entities: consumer, client_ip, route, correlation id  
3. Match WHEN fields  
4. ±30m timeline (001b, distinct IDs, bytes)  
5. Same credential / other routes; same IP / other consumers  
6. Admin/decK gaps (006); IdP correlation  
7. Containment + classification (TP / benign TP / FP / test / open)

---

## Operational gate

1. Sensitive routes/consumers documented; `http-log` complete  
2. Positive/negative tests pass  
3. Exceptions narrow + expiry  
4. Alert pivots + runbook  
5. A/F/I/J/C playbooks  
6. Owner, version, quarterly 006/009 review  

Baseline thresholds for at least one business day.

---

## Summary

| Goal | On Kong | In SIEM |
|------|---------|---------|
| Stuffing | auth + RLA + bot + IP | 001, 001b, 004 |
| BOLA early | ACL/OPA + logs | 002 |
| URI/injection | request-validator (+ WAF) | 008 |
| Slow exfil | RLA + masking | 005, 007 |
| Config holes | decK CI | 006 |
| Blind spots | pipeline + synthetic probe | 009 |

DETECTION ENGINEERING 2026 WHEN/GROUP/WITHIN/THEN maps cleanly onto Kong `http-log` (`consumer`, `uri`, `status`, `response.size`). Automation changes how fast thresholds trip—not the rule shape.
