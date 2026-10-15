#!/usr/bin/env python3
"""Generate Kong SIEM Detection Grafana dashboard JSON."""
from __future__ import annotations

import json
from pathlib import Path

OUT = Path(__file__).resolve().parent / "siem-detection.json"
DS = {"type": "loki", "uid": "loki"}


def loki_target(expr: str, ref: str = "A", *, instant: bool = False, legend: str = "") -> dict:
    t = {
        "datasource": DS,
        "expr": expr,
        "queryType": "instant" if instant else "range",
        "refId": ref,
    }
    if legend:
        t["legendFormat"] = legend
    return t


def row(pid: int, title: str, y: int, collapsed: bool = False) -> dict:
    return {
        "collapsed": collapsed,
        "gridPos": {"h": 1, "w": 24, "x": 0, "y": y},
        "id": pid,
        "title": title,
        "type": "row",
        "panels": [],
    }


def stat(pid: int, title: str, expr: str, x: int, y: int, w: int = 4, h: int = 4, *, steps=None, desc: str = "") -> dict:
    steps = steps or [
        {"color": "blue", "value": None},
        {"color": "green", "value": 1},
    ]
    return {
        "datasource": DS,
        "description": desc,
        "fieldConfig": {
            "defaults": {
                "color": {"mode": "thresholds"},
                "thresholds": {"mode": "absolute", "steps": steps},
                "unit": "short",
            },
            "overrides": [],
        },
        "gridPos": {"h": h, "w": w, "x": x, "y": y},
        "id": pid,
        "options": {
            "colorMode": "background",
            "graphMode": "area",
            "justifyMode": "auto",
            "orientation": "auto",
            "reduceOptions": {"calcs": ["sum"], "fields": "", "values": False},
            "textMode": "auto",
        },
        "targets": [loki_target(expr, instant=True)],
        "title": title,
        "type": "stat",
    }


def gauge(pid: int, title: str, expr: str, x: int, y: int, w: int = 4, h: int = 5, *, desc: str = "") -> dict:
    return {
        "datasource": DS,
        "description": desc,
        "fieldConfig": {
            "defaults": {
                "color": {"mode": "thresholds"},
                "max": 100,
                "min": 0,
                "thresholds": {
                    "mode": "absolute",
                    "steps": [
                        {"color": "green", "value": None},
                        {"color": "blue", "value": 20},
                        {"color": "yellow", "value": 40},
                        {"color": "orange", "value": 60},
                        {"color": "red", "value": 80},
                    ],
                },
                "unit": "short",
            },
            "overrides": [],
        },
        "gridPos": {"h": h, "w": w, "x": x, "y": y},
        "id": pid,
        "options": {
            "minmaxShow": True,
            "orientation": "auto",
            "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
            "showThresholdLabels": True,
            "showThresholdMarkers": True,
        },
        "targets": [loki_target(expr, instant=True)],
        "title": title,
        "type": "gauge",
        "transformations": [],
    }


def timeseries(
    pid: int,
    title: str,
    targets: list[dict],
    x: int,
    y: int,
    w: int = 12,
    h: int = 7,
    *,
    bars: bool = False,
    overrides: list | None = None,
    fill_opacity: int | None = None,
    legend_calcs: list | None = None,
) -> dict:
    fill = fill_opacity if fill_opacity is not None else (55 if bars else 15)
    return {
        "datasource": DS,
        "fieldConfig": {
            "defaults": {
                "color": {"mode": "palette-classic"},
                "custom": {
                    "drawStyle": "bars" if bars else "line",
                    "fillOpacity": fill,
                    "gradientMode": "scheme" if bars else "opacity",
                    "lineWidth": 2,
                    "barAlignment": 0,
                    "barWidthFactor": 0.85,
                    "pointSize": 5,
                    "showPoints": "never" if bars else "auto",
                    "spanNulls": False,
                    "stacking": {"group": "A", "mode": "normal" if bars else "none"},
                },
                "unit": "short",
            },
            "overrides": overrides or [],
        },
        "gridPos": {"h": h, "w": w, "x": x, "y": y},
        "id": pid,
        "options": {
            "legend": {
                "calcs": legend_calcs or ["sum", "max"],
                "displayMode": "table",
                "placement": "right",
                "showLegend": True,
            },
            "tooltip": {"mode": "multi", "sort": "desc"},
        },
        "targets": targets,
        "title": title,
        "type": "timeseries",
    }


def piechart(pid: int, title: str, targets: list[dict], x: int, y: int, w: int = 6, h: int = 9, *, desc: str = "") -> dict:
    return {
        "datasource": DS,
        "description": desc,
        "fieldConfig": {
            "defaults": {
                "color": {"mode": "palette-classic"},
                "unit": "short",
                "custom": {},
            },
            "overrides": [
                {"matcher": {"id": "byName", "options": "401/403"}, "properties": [{"id": "color", "value": {"fixedColor": "#F2495C", "mode": "fixed"}}]},
                {"matcher": {"id": "byName", "options": "429"}, "properties": [{"id": "color", "value": {"fixedColor": "#FF9830", "mode": "fixed"}}]},
                {"matcher": {"id": "byName", "options": "200"}, "properties": [{"id": "color", "value": {"fixedColor": "#73BF69", "mode": "fixed"}}]},
                {"matcher": {"id": "byName", "options": "heartbeat"}, "properties": [{"id": "color", "value": {"fixedColor": "#5794F2", "mode": "fixed"}}]},
            ],
        },
        "gridPos": {"h": h, "w": w, "x": x, "y": y},
        "id": pid,
        "options": {
            "displayLabels": ["name", "percent"],
            "legend": {
                "displayMode": "table",
                "placement": "bottom",
                "showLegend": True,
                "values": ["value", "percent"],
            },
            "pieType": "donut",
            "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
            "tooltip": {"mode": "single", "sort": "desc"},
        },
        "targets": targets,
        "title": title,
        "type": "piechart",
    }


def _status_color_overrides() -> list:
    return [
        {
            "matcher": {"id": "byName", "options": "401/403"},
            "properties": [
                {"id": "color", "value": {"fixedColor": "#F2495C", "mode": "fixed"}},
                {"id": "custom.fillOpacity", "value": 70},
            ],
        },
        {
            "matcher": {"id": "byName", "options": "429"},
            "properties": [{"id": "color", "value": {"fixedColor": "#FF9830", "mode": "fixed"}}],
        },
        {
            "matcher": {"id": "byName", "options": "200"},
            "properties": [{"id": "color", "value": {"fixedColor": "#73BF69", "mode": "fixed"}}],
        },
        {
            "matcher": {"id": "byName", "options": "heartbeat"},
            "properties": [{"id": "color", "value": {"fixedColor": "#5794F2", "mode": "fixed"}}],
        },
    ]


def _status_trend_targets(*, instant: bool = False) -> list[dict]:
    return [
        loki_target(
            f"sum(count_over_time({CUST} | json | response_status=`401` or response_status=`403` [${'__range' if instant else '__interval'}]))",
            "A",
            legend="401/403",
            instant=instant,
        ),
        loki_target(
            f"sum(count_over_time({CUST} | json | response_status=`429` [${'__range' if instant else '__interval'}]))",
            "B",
            legend="429",
            instant=instant,
        ),
        loki_target(
            f"sum(count_over_time({CUST} | json | response_status=`200` [${'__range' if instant else '__interval'}]))",
            "C",
            legend="200",
            instant=instant,
        ),
        loki_target(
            f"sum(count_over_time({HB} [${'__range' if instant else '__interval'}]))",
            "D",
            legend="heartbeat",
            instant=instant,
        ),
    ]


def logs(pid: int, title: str, expr: str, x: int, y: int, w: int = 12, h: int = 7) -> dict:
    return {
        "datasource": DS,
        "gridPos": {"h": h, "w": w, "x": x, "y": y},
        "id": pid,
        "options": {
            "dedupStrategy": "none",
            "enableLogDetails": True,
            "prettifyLogMessage": True,
            "showCommonLabels": False,
            "showLabels": False,
            "showTime": True,
            "sortOrder": "Descending",
            "wrapLogMessage": True,
        },
        "targets": [loki_target(expr)],
        "title": title,
        "type": "logs",
    }


def geomap(pid: int, title: str, expr: str, x: int, y: int, w: int = 14, h: int = 10, *, desc: str = "") -> dict:
    """Grafana Geomap markers from Loki labels lat/lon/country (demo Geo headers)."""
    return {
        "datasource": DS,
        "description": desc,
        "fieldConfig": {
            "defaults": {
                "color": {"mode": "thresholds"},
                "thresholds": {
                    "mode": "absolute",
                    "steps": [
                        {"color": "green", "value": None},
                        {"color": "yellow", "value": 5},
                        {"color": "red", "value": 15},
                    ],
                },
            },
            "overrides": [],
        },
        "gridPos": {"h": h, "w": w, "x": x, "y": y},
        "id": pid,
        "options": {
            # osm-standard: no Mapbox/Google API key (CARTO default can prompt / fail offline)
            "basemap": {"name": "OpenStreetMap", "type": "osm-standard", "config": {}},
            "controls": {
                "mouseWheelZoom": True,
                "showAttribution": True,
                "showDebug": False,
                "showMeasure": False,
                "showScale": False,
                "showZoom": True,
            },
            "layers": [
                {
                    "type": "markers",
                    "name": "Threat origins",
                    "config": {
                        "showLegend": True,
                        "style": {
                            "color": {"field": "Value", "fixed": "dark-red"},
                            "opacity": 0.85,
                            "rotation": {"fixed": 0, "max": 360, "min": -360, "mode": "mod"},
                            "size": {
                                "field": "Value",
                                "fixed": 8,
                                "max": 30,
                                "min": 6,
                            },
                            "symbol": {"fixed": "img/icons/marker/circle.svg", "mode": "fixed"},
                            "textConfig": {
                                "fontSize": 12,
                                "offsetX": 0,
                                "offsetY": 0,
                                "textAlign": "center",
                                "textBaseline": "middle",
                            },
                        },
                    },
                    "location": {
                        "mode": "coords",
                        "latitude": "lat",
                        "longitude": "lon",
                    },
                    "tooltip": True,
                    "filterData": {"id": "byRefId", "options": "A"},
                }
            ],
            "tooltip": {"mode": "details"},
            "view": {
                "allLayers": True,
                "id": "coords",
                "lat": 25,
                "lon": 80,
                "zoom": 1.4,
            },
        },
        "targets": [loki_target(expr, instant=True, legend="{{country}}")],
        "title": title,
        "type": "geomap",
    }


def text_panel(pid: int, title: str, md: str, x: int, y: int, w: int = 8, h: int = 4) -> dict:
    return {
        "gridPos": {"h": h, "w": w, "x": x, "y": y},
        "id": pid,
        "options": {
            "code": {"language": "markdown", "showLineNumbers": False},
            "content": md,
            "mode": "markdown",
        },
        "title": title,
        "type": "text",
    }


def scenario_md(*, what: str, means: str, signal: str, action: str) -> str:
    return (
        f"**What** — {what}\n\n"
        f"**Why it matters** — {means}\n\n"
        f"**What to look for** — {signal}\n\n"
        f"**Response** — {action}"
    )


# --- LogQL snippets ---
BASE = '{log_source="http-log"}'
SIEM = f'{BASE} |= `/siem-demo/`'
CUST = f'{BASE} |= `/siem-demo/loan/customers`'
OPEN = f'{BASE} |= `/siem-demo/loan/open`'
HB = f'{BASE} |= `/siem-demo/heartbeat`'
BULK = f'{BASE} |= `/siem-demo/loan/customers` |= `/bulk`'

# Demo Geo headers in http-log JSON (ui/app.py X-Demo-*).
# Header key order is unstable — extract lat/lon/country with separate regexp stages.
GEO_PARSE = (
    f"{SIEM} |= `x-demo-lat` "
    r'| regexp `x-demo-lat":"(?P<lat>[^"]+)` '
    r'| regexp `x-demo-lon":"(?P<lon>[^"]+)` '
    r'| regexp `x-demo-country":"(?P<country>[^"]+)`'
)
GEO_BY_LOC = f"sum by (lat, lon, country) (count_over_time({GEO_PARSE} [$__range]))"
GEO_BY_COUNTRY = f"sum by (country) (count_over_time({GEO_PARSE} [$__interval]))"

# Threat score — item weights with per-item caps (total max 100). Loki has no clamp_max.
URI_SIG = r'(?i)(\.\./|%2e%2e)'
UA_SIG = r'(?i)(python-requests|curl/|siem-bot)'


def _or0(metric: str) -> str:
    # Empty vector breaks binary + in LogQL; coerce missing series to 0.
    return f"({metric} or vector(0))"


def _cap(expr: str, n: int) -> str:
    """min(expr, n) via comparison (LogQL lacks clamp_max / min(a,b) here)."""
    e = f"({expr})"
    return f"(({e} > bool {n}) * {n} + ({e} <= bool {n}) * {e})"


_AUTH = f"sum(count_over_time({CUST} | json | response_status=`401` or response_status=`403` [$__range]))"
_RL = f"sum(count_over_time({CUST} | json | response_status=`429` [$__range]))"
_UA = f"sum(count_over_time({CUST} |~ `{UA_SIG}` [$__range]))"
_URI = f"sum(count_over_time({SIEM} |~ `{URI_SIG}` [$__range]))"
_BULK200 = f"sum(count_over_time({BULK} | json | response_status=`200` [$__range]))"

# Max 100 = auth 40 + 429 20 + UA 20 + URI 20 (per-item caps)
SCORE = (
    f"{_cap(_or0(_AUTH), 40)} + "
    f"{_cap(f'2*{_or0(_RL)}', 20)} + "
    f"{_cap(f'5*{_or0(_UA)}', 20)} + "
    f"{_cap(f'10*{_or0(_URI)}', 20)}"
)

SEVERE = f"{_or0(_AUTH)} + {_or0(_URI)} + {_or0(_BULK200)}"

SCORE_CRITERIA_MD = """**Risk alert score (0–100)**

Based on siem-demo http-log in the selected time range (`$__range`).

| Item | Points | Cap |
|------|--------|-----|
| Auth failure 401/403 | 1 / event | **40** |
| Rate limit 429 | 2 / event | **20** |
| Script UA | 5 / event | **20** |
| URI traversal | 10 / event | **20** |
| **Total** | | **100** |

**Levels** — 0–19 normal · 20–39 watch · 40–59 caution · 60–79 elevated · 80–100 critical
"""


def build() -> dict:
    panels: list[dict] = []
    y = 0
    pid = 1

    # ===== Overview =====
    panels.append(row(pid, "Overview — Cyber posture", y))
    pid += 1
    y += 1

    panels.append(
        gauge(
            pid,
            "Risk alert score",
            SCORE,
            0,
            y,
            w=4,
            h=7,
            desc="0–100. See Scoring criteria on the right for weights and caps.",
        )
    )
    pid += 1
    panels.append(text_panel(pid, "Scoring criteria", SCORE_CRITERIA_MD, 4, y, w=5, h=7))
    pid += 1
    panels.append(
        stat(
            pid,
            "Risk events",
            f"sum(count_over_time({SIEM} [$__range]))",
            9,
            y,
            w=3,
            h=3,
            steps=[{"color": "blue", "value": None}, {"color": "orange", "value": 50}, {"color": "red", "value": 200}],
            desc="All siem-demo http-log events",
        )
    )
    pid += 1
    panels.append(
        stat(
            pid,
            "High-risk attempts",
            SEVERE,
            12,
            y,
            w=3,
            h=3,
            steps=[{"color": "green", "value": None}, {"color": "yellow", "value": 1}, {"color": "red", "value": 20}],
            desc="401/403 + URI attacks + bulk 200",
        )
    )
    pid += 1
    panels.append(
        stat(
            pid,
            "Auth failures",
            f"sum(count_over_time({CUST} | json | response_status=`401` or response_status=`403` [$__range]))",
            15,
            y,
            w=3,
            h=3,
            steps=[{"color": "green", "value": None}, {"color": "orange", "value": 10}, {"color": "red", "value": 30}],
        )
    )
    pid += 1
    panels.append(
        stat(
            pid,
            "429 rate limit",
            f"sum(count_over_time({CUST} | json | response_status=`429` [$__range]))",
            18,
            y,
            w=3,
            h=3,
            steps=[{"color": "green", "value": None}, {"color": "yellow", "value": 1}, {"color": "red", "value": 10}],
        )
    )
    pid += 1
    panels.append(
        stat(
            pid,
            "Heartbeat",
            f"sum(count_over_time({HB} [$__range]))",
            21,
            y,
            w=3,
            h=3,
            steps=[{"color": "red", "value": None}, {"color": "green", "value": 1}],
            desc="0 may indicate visibility gap (KG-API-009)",
        )
    )
    pid += 1
    panels.append(
        text_panel(
            pid,
            "Ops notes",
            (
                "**Kong SIEM** — `siem-demo`\n\n"
                "- Demo UI: set `SIEM_UI_PORT` (default 3071)\n"
                "- Geomap: demo coordinate headers (production: GeoIP)\n"
                "- Rows below: scenario text + charts + logs\n"
            ),
            9,
            y + 3,
            w=15,
            h=4,
        )
    )
    pid += 1
    y += 7

    # Status mix — donut + stacked bars
    panels.append(row(pid, "Trends — HTTP status", y))
    pid += 1
    y += 1
    panels.append(
        piechart(
            pid,
            "Status mix (range total)",
            _status_trend_targets(instant=True),
            0,
            y,
            w=7,
            h=10,
            desc="Share of 401/403, 429, 200, and heartbeat in the selected range",
        )
    )
    pid += 1
    panels.append(
        timeseries(
            pid,
            "Status trend — stacked bars",
            _status_trend_targets(instant=False),
            7,
            y,
            w=17,
            h=10,
            bars=True,
            overrides=_status_color_overrides(),
            fill_opacity=75,
            legend_calcs=["sum", "max", "lastNotNull"],
        )
    )
    pid += 1
    y += 10

    panels.append(
        geomap(
            pid,
            "Global threat map (source)",
            GEO_BY_LOC,
            0,
            y,
            w=14,
            h=10,
            desc=(
                "Source geography for SIEM events. "
                "Private Docker IPs cannot use MaxMind; the demo uses X-Demo-Lat/Lon/Country headers."
            ),
        )
    )
    pid += 1
    panels.append(
        timeseries(
            pid,
            "Events by country (TOP)",
            [loki_target(GEO_BY_COUNTRY, "A", legend="{{country}}")],
            14,
            y,
            w=10,
            h=5,
            bars=True,
        )
    )
    pid += 1
    panels.append(
        timeseries(
            pid,
            "Attacker TOP — client_ip",
            [
                loki_target(
                    f"sum by (client_ip) (count_over_time({SIEM} | json [$__interval]))",
                    "A",
                    legend="{{client_ip}}",
                )
            ],
            14,
            y + 5,
            w=10,
            h=5,
            bars=True,
        )
    )
    pid += 1
    y += 10
    panels.append(logs(pid, "Recent SIEM events (all)", SIEM, 0, y, w=24, h=7))
    pid += 1
    y += 7

    # ===== Scenario helper =====
    def scenario(
        title: str,
        *,
        note: str,
        judge: str,
        stat_title: str,
        stat_expr: str,
        graph_targets: list[dict],
        log_expr: str,
        steps=None,
        collapsed: bool = False,
    ) -> None:
        nonlocal y, pid
        panels.append(row(pid, title, y, collapsed=collapsed))
        pid += 1
        y += 1
        panels.append(text_panel(pid, "Scenario", note, 0, y, w=12, h=5))
        pid += 1
        panels.append(stat(pid, stat_title, stat_expr, 12, y, w=4, h=5, steps=steps))
        pid += 1
        panels.append(text_panel(pid, "Verdict", judge, 16, y, w=8, h=5))
        pid += 1
        panels.append(timeseries(pid, "Trend", graph_targets, 0, y + 5, w=12, h=7))
        pid += 1
        panels.append(logs(pid, "Related logs", log_expr, 12, y + 5, w=12, h=7))
        pid += 1
        y += 12

    scenario(
        "KG-API-001 — Auth failure burst (credential stuffing)",
        note=scenario_md(
            what="Many calls to the sensitive API (`/siem-demo/loan/customers`) with a **bad apikey** in a short window",
            means="Key/token stuffing or automated auth probing. Higher priority when consumer is null and one IP dominates",
            signal="Spike in **401/403** on the right totals/trend, skewed bars by client_ip, consecutive failures in logs",
            action="Block IP/UA, review bot-detection and key rollover. If 200 follows, escalate to **001b / 007**",
        ),
        judge=(
            "**Demo** — UI `KG-API-001` → **Run** / **Evaluate**\n\n"
            "**Fired (demo)** — 401/403 ≥ 10 within ~2m\n\n"
            "**Response type** — A (account/session)"
        ),
        stat_title="401/403 total",
        stat_expr=f"sum(count_over_time({CUST} | json | response_status=`401` or response_status=`403` [$__range]))",
        graph_targets=[
            loki_target(
                f"sum(count_over_time({CUST} | json | response_status=`401` or response_status=`403` [$__interval]))",
                "A",
                legend="401/403",
            ),
            loki_target(
                f"sum by (client_ip) (count_over_time({CUST} | json | response_status=`401` or response_status=`403` [$__interval]))",
                "B",
                legend="{{client_ip}}",
            ),
        ],
        log_expr=f"{CUST} | json | response_status=`401` or response_status=`403`",
        steps=[{"color": "green", "value": None}, {"color": "orange", "value": 10}, {"color": "red", "value": 30}],
    )

    scenario(
        "KG-API-001b — Fail then success",
        note=scenario_md(
            what="A streak of **401/403** followed by **200** on the same sensitive route",
            means="Valid credentials obtained after guessing/stuffing, or session takeover",
            signal="Trend shows fail curve then success(200). Confirm same client_ip timeline in logs",
            action="Revoke the consumer key, check IdP sessions. If ID walk or bulk follows → **007**",
        ),
        judge=(
            "**Demo** — UI `KG-API-001b` → **Run** / **Evaluate**\n\n"
            "**Fired (demo)** — fails ≥ 3 then success ≥ 1\n\n"
            "**Response type** — A"
        ),
        stat_title="401/403 total",
        stat_expr=f"sum(count_over_time({CUST} | json | response_status=`401` or response_status=`403` [$__range]))",
        graph_targets=[
            loki_target(
                f"sum(count_over_time({CUST} | json | response_status=`401` or response_status=`403` [$__interval]))",
                "A",
                legend="fail",
            ),
            loki_target(
                f"sum(count_over_time({CUST} | json | response_status=`200` [$__interval]))",
                "B",
                legend="success",
            ),
        ],
        log_expr=CUST,
        steps=[{"color": "green", "value": None}, {"color": "yellow", "value": 3}, {"color": "red", "value": 10}],
    )

    scenario(
        "KG-API-002 — BOLA / ID enumeration",
        note=scenario_md(
            what="Many **distinct IDs** on `/customers/{id}` with a valid key in a short window",
            means="Object-level authz flaw (BOLA) or automated browsing when the app returns others' data by ID alone",
            signal="Surge of customers **200**, sequential/scattered IDs in URI logs (demo: distinct-ID threshold)",
            action="Ticket app authz review. Tighten ACL/OPA/validator/limits. Large volume → **005**",
        ),
        judge=(
            "**Demo** — UI `KG-API-002` → **Run** / **Evaluate**\n\n"
            "**Fired (demo)** — distinct customer id ≥ 12 / 2m\n\n"
            "**Response type** — F (+A)"
        ),
        stat_title="customers 200",
        stat_expr=f"sum(count_over_time({CUST} | json | response_status=`200` [$__range]))",
        graph_targets=[
            loki_target(
                f"sum(count_over_time({CUST} | json | response_status=`200` [$__interval]))",
                "A",
                legend="200",
            ),
        ],
        log_expr=f"{CUST} | json | response_status=`200` |~ `/customers/[0-9]+`",
        steps=[{"color": "blue", "value": None}, {"color": "orange", "value": 12}, {"color": "red", "value": 30}],
    )

    scenario(
        "KG-API-003 — Rate limit exceeded",
        note=scenario_md(
            what="Consumer-scoped RLA exceeded → **429**",
            means="Automated scraping/abuse or batch surge. Without limits the same pattern can become quiet exfil",
            signal="429 total/trend spikes. Interleaved 200 and 429 means collection up to the limit",
            action="Revisit limit and identifier (consumer). Sensitive route with no limit → correlate with **006**",
        ),
        judge=(
            "**Demo** — UI `KG-API-003` → **Run** / **Evaluate**\n\n"
            "**Fired (demo)** — 429 ≥ 1\n\n"
            "**Response type** — F"
        ),
        stat_title="429 total",
        stat_expr=f"sum(count_over_time({CUST} | json | response_status=`429` [$__range]))",
        graph_targets=[
            loki_target(
                f"sum(count_over_time({CUST} | json | response_status=`429` [$__interval]))",
                "A",
                legend="429",
            ),
            loki_target(
                f"sum(count_over_time({CUST} | json | response_status=`200` [$__interval]))",
                "B",
                legend="200",
            ),
        ],
        log_expr=f"{CUST} | json | response_status=`429`",
        steps=[{"color": "green", "value": None}, {"color": "yellow", "value": 1}, {"color": "red", "value": 5}],
    )

    scenario(
        "KG-API-004 — Bot / script UA",
        note=scenario_md(
            what="Non-browser UA (`python-requests` / `curl` / `siem-bot`) on a sensitive route",
            means="Script/bot automation. In production, AND with GeoIP/ASN when possible",
            signal="Script UA total, per-UA trend, User-Agent in logs",
            action="Allowlist approved batch UAs. Otherwise bot-detection and IP restriction",
        ),
        judge=(
            "**Demo** — UI `KG-API-004` → **Run** / **Evaluate**\n\n"
            "**Fired (demo)** — matching UA ≥ 1\n\n"
            "**Response type** — F"
        ),
        stat_title="Script UA",
        stat_expr=f"sum(count_over_time({CUST} |~ `{UA_SIG}` [$__range]))",
        graph_targets=[
            loki_target(
                f"sum(count_over_time({CUST} |~ `(?i)python-requests` [$__interval]))",
                "A",
                legend="python-requests",
            ),
            loki_target(
                f"sum(count_over_time({CUST} |~ `(?i)curl/` [$__interval]))",
                "B",
                legend="curl",
            ),
            loki_target(
                f"sum(count_over_time({CUST} |~ `(?i)siem-bot` [$__interval]))",
                "C",
                legend="siem-bot",
            ),
        ],
        log_expr=f"{CUST} |~ `{UA_SIG}`",
        steps=[{"color": "green", "value": None}, {"color": "red", "value": 1}],
    )

    scenario(
        "KG-API-005 — Mass / high-volume exfil",
        note=scenario_md(
            what="Repeated **large 200** responses (e.g. `/customers/{id}/bulk`) for the same identity",
            means="Sensitive data collection via API",
            signal="bulk 200 count, response size sum, bulk share vs all 200",
            action="Disable consumer, RLA 0, estimate impact. With prior auth anomaly → **007**",
        ),
        judge=(
            "**Demo** — UI `KG-API-005` → **Run** / **Evaluate**\n\n"
            "**Fired (demo)** — count ≥ 5 or bytes sum ≥ ~400KB\n\n"
            "**Response type** — I (+A)"
        ),
        stat_title="bulk 200",
        stat_expr=f"sum(count_over_time({BULK} | json | response_status=`200` [$__range]))",
        graph_targets=[
            loki_target(
                f"sum(count_over_time({BULK} | json | response_status=`200` [$__interval]))",
                "A",
                legend="bulk 200",
            ),
            loki_target(
                f"sum(count_over_time({CUST} | json | response_status=`200` [$__interval]))",
                "B",
                legend="all 200",
            ),
        ],
        log_expr=f"{BULK} | json | response_status=`200`",
        steps=[{"color": "blue", "value": None}, {"color": "orange", "value": 5}, {"color": "red", "value": 10}],
    )

    scenario(
        "KG-API-006 — Sensitive route control gap",
        note=scenario_md(
            what="Sensitive path (loan/customer) with **no auth or rate-limit plugin** (demo: `/siem-demo/loan/open`)",
            means="Config/exposure gap to close before traffic alerts",
            signal="open-route call logs + UI **Evaluate** Admin scan gaps (auth/limit missing)",
            action="Enforce auth + RLA via decK/CI. Remove the gap route or attach protective plugins",
        ),
        judge=(
            "**Demo** — UI `KG-API-006` → **Run** (visibility) / **Evaluate** (Admin scan)\n\n"
            "**Fired** — sensitive path missing auth or RLA\n\n"
            "**Response type** — F (config)"
        ),
        stat_title="open route hits",
        stat_expr=f"sum(count_over_time({OPEN} [$__range]))",
        graph_targets=[
            loki_target(
                f"sum(count_over_time({OPEN} [$__interval]))",
                "A",
                legend="open",
            ),
        ],
        log_expr=OPEN,
        steps=[{"color": "green", "value": None}, {"color": "orange", "value": 1}],
    )

    scenario(
        "KG-API-007 — Auth anomaly → mass-read chain",
        note=scenario_md(
            what="**001/001b** fires, then **002 or 005** within a short window",
            means="**Attack chain**: stuffing/theft followed by mass reads (merge as one incident)",
            signal="Auth-fail trend and bulk-200 trend rise in the same window",
            action="Revoke credentials, block IP, temporary route limit. Case types **C+A+I**",
        ),
        judge=(
            "**Demo** — UI `KG-API-007` → **Run** / **Evaluate**\n\n"
            "**Fired** — 001 (or 001b) AND 005 together\n\n"
            "**Response type** — C + A + I"
        ),
        stat_title="Chain signal (401+bulk)",
        stat_expr=(
            f"sum(count_over_time({CUST} | json | response_status=`401` or response_status=`403` [$__range])) "
            f"+ sum(count_over_time({BULK} | json | response_status=`200` [$__range]))"
        ),
        graph_targets=[
            loki_target(
                f"sum(count_over_time({CUST} | json | response_status=`401` or response_status=`403` [$__interval]))",
                "A",
                legend="auth fail",
            ),
            loki_target(
                f"sum(count_over_time({BULK} | json | response_status=`200` [$__interval]))",
                "B",
                legend="bulk 200",
            ),
        ],
        log_expr=f"{CUST} |~ `/loan/customers`",
        steps=[{"color": "green", "value": None}, {"color": "orange", "value": 10}, {"color": "red", "value": 30}],
    )

    scenario(
        "KG-API-008 — URI traversal / metachar",
        note=scenario_md(
            what="Request URI contains path-manipulation / encoding signatures such as `../`, `%2e%2e`",
            means="Edge/app attack attempt. Escalate if success or large response",
            signal="Signature match count/trend and request.uri in logs",
            action="validator/WAF and IP block. Normalize paths and review app authz",
        ),
        judge=(
            "**Demo** — UI `KG-API-008` → **Run** / **Evaluate**\n\n"
            "**Fired (demo)** — URI signature ≥ 1\n\n"
            "**Response type** — F"
        ),
        stat_title="Signature matches",
        stat_expr=f"sum(count_over_time({SIEM} |~ `{URI_SIG}` [$__range]))",
        graph_targets=[
            loki_target(
                f"sum(count_over_time({SIEM} |~ `{URI_SIG}` [$__interval]))",
                "A",
                legend="traversal",
            ),
        ],
        log_expr=f"{SIEM} |~ `{URI_SIG}`",
        steps=[{"color": "green", "value": None}, {"color": "red", "value": 1}],
    )

    scenario(
        "KG-API-009 — Heartbeat silence (detection health)",
        note=scenario_md(
            what="Proxy is up but **heartbeat http-log stops** (intentional Heartbeat OFF demo)",
            means="Detection/telemetry gap. Loss of visibility is the incident—not an attack payload",
            signal="Heartbeat line = 0 (red) while other siem traffic / proxy may still look healthy",
            action="Restore http-log/Fluent/Loki and hunt the blind window. Response type **J**",
        ),
        judge=(
            "**Demo** — UI Heartbeat OFF or `KG-API-009` **Run** / **Evaluate**\n\n"
            "**Fired (demo)** — ≥15s silence, 0 events on route, proxy up\n\n"
            "**Response type** — J"
        ),
        stat_title="Heartbeat lines",
        stat_expr=f"sum(count_over_time({HB} [$__range]))",
        graph_targets=[
            loki_target(
                f"sum(count_over_time({HB} [$__interval]))",
                "A",
                legend="heartbeat",
            ),
            loki_target(
                f"sum(count_over_time({SIEM} [$__interval]))",
                "B",
                legend="all siem",
            ),
        ],
        log_expr=HB,
        steps=[{"color": "red", "value": None}, {"color": "green", "value": 1}],
    )

    return {
        "annotations": {"list": []},
        "editable": True,
        "fiscalYearStartMonth": 0,
        "graphTooltip": 1,
        "id": None,
        "links": [
            {
                "asDropdown": False,
                "icon": "external link",
                "includeVars": False,
                "keepTime": True,
                "tags": [],
                "targetBlank": True,
                "title": "Demo UI",
                "tooltip": "",
                "type": "link",
                "url": "http://localhost:3071",
            }
        ],
        "panels": panels,
        "refresh": "10s",
        "schemaVersion": 39,
        "tags": ["kong", "siem", "siem-demo", "detection"],
        "templating": {"list": []},
        "time": {"from": "now-30m", "to": "now"},
        "timepicker": {},
        "timezone": "browser",
        "title": "Kong SIEM Detection (siem-demo)",
        "uid": "kong-siem-detection",
        "version": 2,
    }


def main() -> None:
    dash = build()
    OUT.write_text(json.dumps(dash, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {OUT} ({len(dash['panels'])} panels)")


if __name__ == "__main__":
    main()
