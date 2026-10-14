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

## Rule cards

Tune production WITHIN / thresholds after a business baseline.  
**Loki LogQL** examples below use short validation windows (2–5m).

### KG-API-001 Auth failure burst (credential stuffing / key spray)

| Field | Content |
|-------|---------|
| Domain | Account / auth |
| Response · timeline | **A**, auth-style |
| ATT&CK | T1110 Brute Force |
| Severity · window | High, **5m** (ops) / demo **2m · ≥10** |
| Telemetry | Kong `http-log` |
| Key fields | `client_ip`, `response.status`, `request.uri`, `consumer`, `request.headers.user-agent`, `route.name` |
| **WHEN** | Same `client_ip` (or same `route`): `response.status in (401, 403)` exceeds baseline (e.g. ≥50 / 5m). Prefer when `consumer` is often null |
| **GROUP BY** | `client_ip` + `route.name` |
| **THEN** | High alert. If success follows on the same IP → escalate to KG-API-001b / 007 |
| Plugins | `openid-connect` / `key-auth`, `bot-detection`, `ip-restriction` |
| Tuning | Exclude health-check / monitor IPs. Tie post-deploy key-expiry 401s to change windows |
| Safety check | Call with bad keys N times → one alert + test tag |
| DE-like | DE-001 |

```text
WHEN count(status IN {401,403}) BY client_ip, route.name
WITHIN 5m
THRESHOLD >= baseline * 3 OR >= 50
THEN alert high "kong_auth_failure_burst"
```

```logql
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
```

Fire when the series value is ≥ 10 (demo threshold).

---

### KG-API-001b Fail then success (compromise / bypass precursor)

| Field | Content |
|-------|---------|
| Domain | Account / auth |
| Response · timeline | **A**, auth-style |
| ATT&CK | T1110, T1078 |
| Severity · window | High, **10m** (ops) / demo **3m · ≥3 fails then 200** |
| **WHEN** | Same `client_ip` (or consumer candidate): consecutive `401/403` then `status=200` on the same sensitive `route` in-window |
| **RELATE BY** | `client_ip` → `consumer` at success |
| **THEN** | High. If ID walk or bulk follows → KG-API-007 |
| Plugins | Auth plugin + `http-log` |
| Tuning | Suppress normal key rotation / gateway retries |
| Safety check | Replay fail events then one success → one correlated case |
| DE-like | DE-002 |

```text
WHEN auth_failures(ip) AND success(ip, route) WITHIN 10m
THEN alert high "kong_auth_fail_then_success"
```

```logql
# failures
{log_source="http-log"} |= `/loan/customers`
  | json
  | response_status = "401" or response_status = "403"

# success (cross by client_ip in Explore)
{log_source="http-log"} |= `/loan/customers`
  | json
  | response_status = "200"
```

Sequence correlation belongs to the SIEM rule / correlation engine.

---

### KG-API-002 Fast resource ID enumeration (BOLA / authz gap)

| Field | Content |
|-------|---------|
| Domain | Web / app / collection |
| Response · timeline | **F** (+ **A** if confirmed), endpoint-style |
| ATT&CK | T1190; sensitive reads ≈ T1005 / T1213 via API |
| Severity · window | **Critical**, **10m** (ops) / demo **2m · distinct ID ≥12** |
| **WHEN** | Same `consumer` (else `client_ip`) hits many distinct resource IDs quickly. Example: `/customers/{id}` distinct `{id}` ≥ 30 / 10m with high `200` rate |
| **GROUP BY** | `consumer.username` (else `client_ip`) + `route.name` |
| **THEN** | Critical. Ticket app object-level authz (F) |
| Plugins | `acl`, OPA/policy, `request-validator`, rate limit |
| Tuning | Separate limits/allowlists for batch/settlement consumers. Extract ID via path regex |
| Safety check | Replay sequential dummy IDs on a test route |
| DE-like | DE-071 mapped to API path IDs (not DE-046 Path Traversal) |

```text
WHEN distinct_count(extract_id(request.uri)) BY consumer
     WHERE status = 200 AND route IN sensitive_routes
WITHIN 10m
THRESHOLD >= 30
THEN alert critical "kong_bola_id_enumeration"
```

```logql
{log_source="http-log"} |= `/loan/customers`
  | json
  | response_status = "200"
  | regexp `/customers/(?P<resource_id>[^/?]+)`
```

Aggregate `count_distinct(resource_id)` by `client_ip` or `consumer_username`.

---

### KG-API-003 Rate-limit proximity / exceed (automated collection)

| Field | Content |
|-------|---------|
| Domain | Web / app |
| Response · timeline | **F**, endpoint-style |
| ATT&CK | T1110 (automated abuse context) |
| Severity · window | High, **15m** (ops) / demo **2m · 429 ≥1** |
| Telemetry | `http-log` + `X-RateLimit-*` / `RateLimit-*` |
| **WHEN** | (a) `status=429` over threshold per consumer/IP, or (b) sustained 200s with remaining &lt; 10% of limit |
| **GROUP BY** | `consumer` / `client_ip` |
| **THEN** | High. If route has no limit → correlate with KG-API-006 |
| Plugins | `rate-limiting-advanced` (`identifier: consumer`) |
| Tuning | Peak-hour baseline. Prefer consumer over NAT IP |
| Safety check | Exceed limit with a test consumer → 429 + one alert |
| DE-like | Web abuse + DE-071 precursor |

```logql
sum(count_over_time(
  {log_source="http-log"} |= `/loan/customers`
  | json
  | response_status = "429"
  [2m]
))
```

---

### KG-API-004 Bot / script UA + foreign IP + sensitive route

| Field | Content |
|-------|---------|
| Domain | Web / app / network |
| Response · timeline | **F** (+ **E** if IOC block), endpoint-style |
| ATT&CK | T1071, T1110 |
| Severity · window | High, **15m** |
| **WHEN** | Sensitive `route` with script/non-browser UA (`python-requests`, `curl`, empty UA) or `bot-detection` block, and `client_ip` in disallowed country/ASN |
| **GROUP BY** | `client_ip` + `route.name` |
| **THEN** | High. Overlap with 002/005 → escalate to critical |
| Plugins | `bot-detection`, `ip-restriction`, `openid-connect` |
| Tuning | Signed exceptions for approved batch UA / egress IPs |
| Safety check | Call sensitive route with disallowed UA + test GeoIP |
| DE-like | Public-edge abuse; URI tampering → KG-API-008 / DE-046·047 |

```logql
{log_source="http-log"} |= `/loan/customers`
  | json
  | line_format `{{.request_headers_user_agent}}`
  |~ `(?i)(python-requests|curl|siem-bot)`
```

In production, AND with GeoIP `country` / `asn`.

---

### KG-API-005 Same-identity mass / high-byte success (exfil)

| Field | Content |
|-------|---------|
| Domain | Data collection / exfil |
| Response · timeline | **I** (+ **A**), correlation-style |
| ATT&CK | T1005-like via API |
| Severity · window | **Critical**, **30m** (ops) / demo **3m · count ≥5 or bytes ≥400KB** |
| **WHEN** | Same `consumer` on sensitive route with `status=200` and (a) count ≥ threshold or (b) `sum(response.size)` ≥ threshold (e.g. 50MB or 500 calls / 30m) |
| **GROUP BY** | `consumer.username` + `route.name` |
| **THEN** | Critical. Revoke credentials, set limit 0 (I+A) |
| Plugins | Rate limit, response masking (preventive), `http-log` |
| Tuning | Separate volume baselines for report/settlement consumers. Prefer size AND count |
| Safety check | Repeat dummy large responses with a test consumer |
| DE-like | DE-071, DE-073 on gateway fields |

```text
WHEN sum(response.size) BY consumer, route
     WHERE status = 200 AND route IN pii_routes
WITHIN 30m
THRESHOLD >= 50MB OR count >= 500
THEN alert critical "kong_mass_exfil_via_api"
```

```logql
sum by (consumer_username) (
  count_over_time(
    {log_source="http-log"} |= `/loan/customers`
    | json
    | response_status = "200"
    [3m]
  )
)
```

```logql
sum by (consumer_username) (
  sum_over_time(
    {log_source="http-log"} |= `/loan/customers`
    | json
    | response_status = "200"
    | unwrap response_size [3m]
  )
)
```

---

### KG-API-006 Sensitive route control gap (config / exposure)

| Field | Content |
|-------|---------|
| Domain | Exposure — configuration defect |
| Response · timeline | **F** (config fix), endpoint-style |
| Severity · window | High, **daily batch or on config change** |
| Telemetry | Admin API dump, decK state, CP audit (**not** traffic logs) |
| **WHEN** | Sensitive `paths`/tags missing auth (`key-auth` / `openid-connect` / `jwt`) or `rate-limiting*` |
| **THEN** | High (config). Close the hole before traffic alerts |
| Plugins | CI decK lint / policy guard |
| Safety check | Plant an intentional gap route in staging; confirm one scan hit |
| DE-like | DE-088-like. Telemetry silence → KG-API-009 / DE-091 |

```text
sensitive paths/tags ∩ (no key-auth|openid-connect|jwt|basic-auth
                     OR no rate-limiting|rate-limiting-advanced) → alert
```

Example path substring: `/loan`. In the sample deck, `/siem-demo/loan/open` is the intentional gap.

---

### KG-API-007 Cross-correlate: auth anomaly then mass success

| Field | Content |
|-------|---------|
| Domain | Cross-source correlation |
| Response · timeline | **C** + **A** + **I**, correlation-style |
| ATT&CK | T1110 → T1078 → collection (T1005-like API) |
| Severity · window | **Critical**, **30m** from first event / demo **5m** |
| **WHEN** | Same `client_ip` (or later same `consumer`): KG-API-001 or 001b, then within 30m KG-API-002 or 005 |
| **RELATE BY** | `client_ip` → `consumer` after auth success |
| **THEN** | Critical. Revoke credentials, block IP, temporary route limit. Merge as one incident |
| Safety check | Replay fail-burst → success → dummy ID walk on one timeline |
| DE-like | DE-002 + DE-071/073 chain |

```text
WHEN (auth_burst(ip) OR fail_then_success(ip))
 AND within 30m mass_success(ip OR consumer_bound_to_ip)
THEN alert critical "kong_stuffing_then_exfil_chain"
```

Intersect KG-API-001 IPs with KG-API-005 IPs/consumers in the same window.

---

### KG-API-008 URI / parameter attack signatures (traversal / metachar)

| Field | Content |
|-------|---------|
| Domain | Web / WAF / application |
| Response · timeline | **F**, endpoint-style |
| ATT&CK | T1190, (metachar) T1059 context |
| Severity · window | High–critical, **5m** |
| **WHEN** | `request.uri`/query contains `../`, `%2e%2e`, shell metachar / injection-like patterns, or `request-validator` 400 spikes per IP. Escalate if 200 + large body |
| **GROUP BY** | `client_ip` + `route.name` |
| **THEN** | High/critical. WAF / IP block / app review (F) |
| Plugins | `request-validator`, optional WAF/OPA, `http-log` |
| Tuning | Exclude normal encoded URLs and approved scanners |
| Safety check | Harmless traversal-like strings on a non-sensitive test path |
| DE-like | DE-046, DE-047 |

```logql
sum(count_over_time(
  {log_source="http-log"} |= `/siem-demo/`
  |~ `(?i)(\.\./|%2e%2e|\.\.%2f)`
  [2m]
))
```

---

### KG-API-009 Sensitive-route http-log silence (detection health)

| Field | Content |
|-------|---------|
| Domain | Detection health / telemetry |
| Response · timeline | **J**, endpoint-style |
| ATT&CK | T1562.001 (visibility loss) |
| Severity · window | **Critical**, **10m** (ops) / demo **2m · EPS=0 for ≥15s** |
| Telemetry | Kong http-log EPS in SIEM/Loki, forwarder heartbeat |
| **WHEN** | Proxy/Admin healthy but http-log for sensitive `route`/workspace is 0 (or collapses) vs expected |
| **GROUP BY** | `route.name` / `workspace` / pipeline |
| **THEN** | Critical (status). Restore pipeline + hunt the blind window (J) |
| Tuning | Distinguish low-traffic routes with heartbeat / synthetic probes |
| Safety check | Pause staging forwarder only, or replay zero-EPS metric |
| DE-like | DE-091 (may pair with DE-094 EPS drop) |

```logql
sum(count_over_time(
  {log_source="http-log"} |= `/siem-demo/heartbeat`
  [2m]
))
```

Value 0 while Proxy health is OK → fire 009.

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
