#!/usr/bin/env python3
"""SIEM detection demo: attack runners + Loki/Admin evaluation."""
from __future__ import annotations

import json
import os
import random
import re
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import quote

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore

HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "8080"))
PROXY = os.environ.get("KONG_PROXY_INTERNAL", "http://kong-dp:8000").rstrip("/")
ADMIN = os.environ.get("KONG_ADMIN_INTERNAL", "http://kong-cp:8001").rstrip("/")
ADMIN_TOKEN = os.environ.get("KONG_ADMIN_TOKEN", "kongadmin")
WORKSPACE = os.environ.get("DEMO_WORKSPACE", "siem-demo")
LOKI = os.environ.get("LOKI_URL", "http://loki:3100").rstrip("/")
GRAFANA = os.environ.get("GRAFANA_URL", "http://localhost:3000").rstrip("/")
APIKEY = os.environ.get("DEMO_APIKEY", "siem-good-key")
# Prefer a Proxy path reachable on kong-net (DP :8100 status is often host-only)
STATUS_URL = os.environ.get(
    "KONG_PROXY_HEALTH_URL",
    os.environ.get("KONG_PROXY_INTERNAL", "http://kong-dp:8000").rstrip("/") + "/siem-demo/heartbeat",
)
DEMO_TAG = "siem-test"
STATIC = Path(__file__).resolve().parent / "static"
RULES_PATH = Path(__file__).resolve().parent / "logql" / "rules.yaml"

_BROWSER_UA = "Mozilla/5.0 (SIEM-Demo; compatible) AppleWebKit/537.36"
_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode = ssl.CERT_NONE

# Demo GeoIP stand-in (local Docker IPs have no MaxMind hit). Headers → Loki → Grafana Geomap.
_GEO = {
    "kr": {"lat": "37.5665", "lon": "126.9780", "country": "KR", "city": "Seoul"},
    "us": {"lat": "37.7749", "lon": "-122.4194", "country": "US", "city": "San Francisco"},
    "jp": {"lat": "35.6762", "lon": "139.6503", "country": "JP", "city": "Tokyo"},
    "cn": {"lat": "31.2304", "lon": "121.4737", "country": "CN", "city": "Shanghai"},
    "de": {"lat": "52.5200", "lon": "13.4050", "country": "DE", "city": "Berlin"},
    "br": {"lat": "-23.5505", "lon": "-46.6333", "country": "BR", "city": "Sao Paulo"},
    "in": {"lat": "19.0760", "lon": "72.8777", "country": "IN", "city": "Mumbai"},
    "ru": {"lat": "55.7558", "lon": "37.6173", "country": "RU", "city": "Moscow"},
}
_ATTACK_GEO = ["us", "jp", "cn", "de", "br", "in", "ru"]


def _geo_headers(profile: str = "kr") -> dict[str, str]:
    g = _GEO.get(profile) or _GEO["kr"]
    return {
        "X-Demo-Lat": g["lat"],
        "X-Demo-Lon": g["lon"],
        "X-Demo-Country": g["country"],
        "X-Demo-City": g["city"],
    }

_heartbeat_lock = threading.Lock()
_heartbeat_enabled = True
_heartbeat_stopped_at: float | None = None
_heartbeat_stats = {"ok": 0, "err": 0, "last": None}


def _json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, ensure_ascii=False, indent=2).encode()


def load_rules() -> dict[str, Any]:
    if yaml is None or not RULES_PATH.is_file():
        return {"defaults": {}, "rules": []}
    with RULES_PATH.open(encoding="utf-8") as f:
        return yaml.safe_load(f) or {"defaults": {}, "rules": []}


def rule_by_id(rid: str) -> dict[str, Any] | None:
    for r in load_rules().get("rules") or []:
        if r.get("id") == rid:
            return r
    return None


def http_call(
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
    timeout: float = 30,
) -> tuple[int, dict[str, str], bytes]:
    req = urllib.request.Request(url, data=body, method=method)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=_SSL_CTX))
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, dict(resp.headers.items()), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers.items()) if e.headers else {}, e.read()
    except Exception as e:  # noqa: BLE001 — demo boundary
        return 502, {}, str(e).encode()


def proxy_get(
    path: str,
    headers: dict[str, str] | None = None,
    *,
    geo: str = "kr",
) -> tuple[int, dict[str, str], str]:
    h = {"Accept": "application/json", "X-Demo-Tag": DEMO_TAG}
    h.update(_geo_headers(geo))
    if headers:
        h.update(headers)
        # Re-apply geo if caller did not set coords (setdefault after update would lose overrides)
        if "X-Demo-Lat" not in (headers or {}):
            h.update(_geo_headers(geo))
    code, hdrs, raw = http_call(f"{PROXY}{path}", headers=h)
    return code, hdrs, raw.decode(errors="replace")


def admin_get(path: str) -> tuple[int, Any]:
    code, _, raw = http_call(
        f"{ADMIN}/{WORKSPACE}{path}",
        headers={"Kong-Admin-Token": ADMIN_TOKEN, "Accept": "application/json"},
    )
    try:
        return code, json.loads(raw.decode() or "null")
    except json.JSONDecodeError:
        return code, {"raw": raw.decode(errors="replace")}


def proxy_up() -> bool:
    code, _, _ = http_call(STATUS_URL, timeout=5)
    return 200 <= code < 300


def loki_query_range(lookback_s: int = 180, limit: int = 2000) -> list[dict[str, Any]]:
    end_ns = int(time.time() * 1e9)
    start_ns = end_ns - lookback_s * 1_000_000_000
    q = '{log_source="http-log"}'
    url = (
        f"{LOKI}/loki/api/v1/query_range?"
        + urllib.parse.urlencode(
            {"query": q, "start": start_ns, "end": end_ns, "limit": limit, "direction": "backward"}
        )
    )
    code, _, raw = http_call(url, timeout=20)
    if code != 200:
        return []
    try:
        data = json.loads(raw.decode())
    except json.JSONDecodeError:
        return []
    out: list[dict[str, Any]] = []
    for stream in (data.get("data") or {}).get("result") or []:
        for ts, line in stream.get("values") or []:
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(obj, dict):
                continue
            obj["_ts"] = int(ts)
            out.append(obj)
    out.sort(key=lambda x: x.get("_ts") or 0)
    return out


def _status(ev: dict[str, Any]) -> int | None:
    r = ev.get("response") or {}
    if isinstance(r, dict) and "status" in r:
        try:
            return int(r["status"])
        except (TypeError, ValueError):
            return None
    us = ev.get("upstream_status")
    if us is not None:
        try:
            return int(str(us).split(",")[0].strip())
        except (TypeError, ValueError):
            return None
    return None


def _uri(ev: dict[str, Any]) -> str:
    req = ev.get("request") or {}
    if isinstance(req, dict):
        return str(req.get("uri") or req.get("url") or "")
    return ""


def _ua(ev: dict[str, Any]) -> str:
    req = ev.get("request") or {}
    if not isinstance(req, dict):
        return ""
    headers = req.get("headers") or {}
    if not isinstance(headers, dict):
        return ""
    for k, v in headers.items():
        if str(k).lower() == "user-agent":
            return str(v)
    return ""


def _route_name(ev: dict[str, Any]) -> str:
    route = ev.get("route") or {}
    if isinstance(route, dict):
        return str(route.get("name") or "")
    return ""


def _resp_size(ev: dict[str, Any]) -> int:
    r = ev.get("response") or {}
    if isinstance(r, dict) and r.get("size") is not None:
        try:
            return int(r["size"])
        except (TypeError, ValueError):
            return 0
    return 0


def grafana_explore_url(logql: str) -> str:
    # Minimal Explore left pane for Loki datasource uid "loki"
    pane = {
        "datasource": "loki",
        "queries": [{"refId": "A", "expr": logql.strip(), "queryType": "range"}],
        "range": {"from": "now-15m", "to": "now"},
    }
    left = quote(json.dumps(pane, separators=(",", ":")))
    return f"{GRAFANA}/explore?orgId=1&left={left}"


def filter_route(events: list[dict[str, Any]], contains: str) -> list[dict[str, Any]]:
    return [e for e in events if contains in _uri(e) or contains in _route_name(e)]


# --- evaluators ---


def eval_status_burst(events: list[dict[str, Any]], cfg: dict[str, Any]) -> dict[str, Any]:
    subset = filter_route(events, cfg.get("route_contains", ""))
    statuses = set(cfg.get("statuses") or [])
    hits = [e for e in subset if _status(e) in statuses]
    min_count = int(cfg.get("min_count") or 1)
    fired = len(hits) >= min_count
    return {
        "fired": fired,
        "count": len(hits),
        "threshold": min_count,
        "samples": [_sample(e) for e in hits[-5:]],
    }


def eval_fail_then_success(events: list[dict[str, Any]], cfg: dict[str, Any]) -> dict[str, Any]:
    subset = filter_route(events, cfg.get("route_contains", ""))
    fails = [e for e in subset if _status(e) in set(cfg.get("fail_statuses") or [])]
    ok = [e for e in subset if _status(e) == int(cfg.get("success_status") or 200)]
    min_fails = int(cfg.get("min_fails") or 1)
    fired = len(fails) >= min_fails and len(ok) >= 1
    if fails and ok:
        fired = fired and (ok[-1].get("_ts") or 0) >= (fails[0].get("_ts") or 0)
    return {
        "fired": fired,
        "fail_count": len(fails),
        "success_count": len(ok),
        "samples": [_sample(e) for e in (fails[-3:] + ok[-2:])],
    }


def eval_distinct_ids(events: list[dict[str, Any]], cfg: dict[str, Any]) -> dict[str, Any]:
    subset = [
        e
        for e in filter_route(events, cfg.get("route_contains", ""))
        if _status(e) == int(cfg.get("status") or 200)
    ]
    rx = re.compile(cfg.get("id_regex") or r"/customers/([^/?]+)")
    ids: set[str] = set()
    for e in subset:
        m = rx.search(_uri(e))
        if m:
            ids.add(m.group(1))
    min_d = int(cfg.get("min_distinct") or 1)
    return {
        "fired": len(ids) >= min_d,
        "distinct": len(ids),
        "threshold": min_d,
        "ids_sample": sorted(ids)[:20],
        "samples": [_sample(e) for e in subset[-5:]],
    }


def eval_ua_match(events: list[dict[str, Any]], cfg: dict[str, Any]) -> dict[str, Any]:
    subset = filter_route(events, cfg.get("route_contains", ""))
    subs = [s.lower() for s in (cfg.get("ua_substrings") or [])]
    hits = [e for e in subset if any(s in _ua(e).lower() for s in subs)]
    return {
        "fired": len(hits) >= 1,
        "count": len(hits),
        "samples": [_sample(e) for e in hits[-5:]],
    }


def eval_mass_success(events: list[dict[str, Any]], cfg: dict[str, Any]) -> dict[str, Any]:
    subset = [
        e
        for e in filter_route(events, cfg.get("route_contains", ""))
        if _status(e) == int(cfg.get("status") or 200)
    ]
    # Prefer bulk path for size demos
    bulk = [e for e in subset if "/bulk" in _uri(e)]
    use = bulk or subset
    total = sum(_resp_size(e) for e in use)
    min_count = int(cfg.get("min_count") or 1)
    min_bytes = int(cfg.get("min_bytes_sum") or 0)
    fired = len(use) >= min_count or total >= min_bytes
    return {
        "fired": fired,
        "count": len(use),
        "bytes_sum": total,
        "min_count": min_count,
        "min_bytes_sum": min_bytes,
        "samples": [_sample(e) for e in use[-5:]],
    }


def eval_uri_sig(events: list[dict[str, Any]], cfg: dict[str, Any]) -> dict[str, Any]:
    subset = filter_route(events, cfg.get("route_contains", ""))
    patterns = cfg.get("patterns") or []
    hits = []
    for e in subset:
        uri = _uri(e)
        uri_l = uri.lower()
        if any(p.lower() in uri_l for p in patterns):
            hits.append(e)
    return {
        "fired": len(hits) >= 1,
        "count": len(hits),
        "samples": [_sample(e) for e in hits[-5:]],
    }


def eval_silence(events: list[dict[str, Any]], cfg: dict[str, Any]) -> dict[str, Any]:
    subset = filter_route(events, cfg.get("route_contains", ""))
    max_count = int(cfg.get("max_count") or 0)
    min_silence_s = int(cfg.get("min_silence_s") or 15)
    up = proxy_up() if cfg.get("require_proxy_up") else True
    with _heartbeat_lock:
        hb = dict(_heartbeat_stats)
        enabled = _heartbeat_enabled
        stopped_at = _heartbeat_stopped_at
    # After stop: only count logs newer than stop time (ns)
    if stopped_at and not enabled:
        stop_ns = int(stopped_at * 1e9)
        subset = [e for e in subset if (e.get("_ts") or 0) > stop_ns]
        silenced_for = time.time() - stopped_at
        fired = up and len(subset) <= max_count and silenced_for >= min_silence_s
    else:
        silenced_for = 0.0
        fired = False
    return {
        "fired": fired,
        "count": len(subset),
        "proxy_up": up,
        "heartbeat_enabled": enabled,
        "silenced_for_s": round(silenced_for, 1),
        "min_silence_s": min_silence_s,
        "heartbeat_stats": hb,
        "samples": [_sample(e) for e in subset[-3:]],
    }


def eval_admin_scan(cfg: dict[str, Any]) -> dict[str, Any]:
    code, routes_body = admin_get("/routes?size=100")
    if code != 200:
        return {"fired": False, "error": f"admin routes HTTP {code}", "gaps": []}
    routes = routes_body.get("data") or []
    sens = cfg.get("sensitive_path_substrings") or []
    auth_names = set(cfg.get("require_any_auth") or [])
    limit_names = set(cfg.get("require_any_limit") or [])
    gaps = []
    for route in routes:
        paths = route.get("paths") or []
        if not any(any(s in p for s in sens) for p in paths):
            continue
        rname = route.get("name")
        pc, plugins_body = admin_get(f"/routes/{rname}/plugins")
        plugins = (plugins_body.get("data") if pc == 200 else []) or []
        # also service-level
        svc = (route.get("service") or {}).get("name") or (route.get("service") or {}).get("id")
        if svc:
            sc, sp = admin_get(f"/services/{svc}/plugins")
            if sc == 200:
                plugins = list(plugins) + list(sp.get("data") or [])
        names = {p.get("name") for p in plugins if p.get("enabled", True)}
        has_auth = bool(names & auth_names)
        has_limit = bool(names & limit_names)
        if not has_auth or not has_limit:
            gaps.append(
                {
                    "route": rname,
                    "paths": paths,
                    "plugins": sorted(names),
                    "missing_auth": not has_auth,
                    "missing_limit": not has_limit,
                }
            )
    return {"fired": len(gaps) >= 1, "gaps": gaps, "route_count": len(routes)}


def eval_chain(events: list[dict[str, Any]], cfg: dict[str, Any]) -> dict[str, Any]:
    first_id = cfg.get("first") or "KG-API-001"
    second_id = cfg.get("second") or "KG-API-005"
    r1 = rule_by_id(first_id)
    r2 = rule_by_id(second_id)
    if not r1 or not r2:
        return {"fired": False, "error": "missing chained rules"}
    e1 = evaluate_rule(r1, events)
    e2 = evaluate_rule(r2, events)
    fired = bool(e1.get("fired")) and bool(e2.get("fired"))
    return {"fired": fired, "first": e1, "second": e2}


def _sample(e: dict[str, Any]) -> dict[str, Any]:
    return {
        "uri": _uri(e),
        "status": _status(e),
        "size": _resp_size(e),
        "ua": _ua(e)[:80],
        "route": _route_name(e),
        "client_ip": e.get("client_ip"),
        "consumer": ((e.get("consumer") or {}) if isinstance(e.get("consumer"), dict) else {}).get(
            "username"
        ),
    }


def evaluate_rule(rule: dict[str, Any], events: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    cfg = rule.get("eval") or {}
    etype = cfg.get("type")
    lookback = rule.get("lookback") or "2m"
    lookback_s = _parse_lookback(lookback)

    if etype == "admin_scan":
        result = eval_admin_scan(cfg)
    else:
        if events is None:
            events = [
                e
                for e in loki_query_range(lookback_s)
                if "/siem-demo/" in _uri(e) or "siem-demo" in _route_name(e)
            ]
        dispatch = {
            "status_burst": eval_status_burst,
            "fail_then_success": eval_fail_then_success,
            "distinct_ids": eval_distinct_ids,
            "ua_match": eval_ua_match,
            "mass_success": eval_mass_success,
            "uri_sig": eval_uri_sig,
            "silence": eval_silence,
            "chain": eval_chain,
        }
        fn = dispatch.get(etype or "")
        if not fn:
            result = {"fired": False, "error": f"unknown eval type {etype}"}
        elif etype == "chain":
            result = fn(events, cfg)  # type: ignore[misc]
        else:
            result = fn(events, cfg)  # type: ignore[misc]

    logql = (rule.get("logql") or "").strip() or _default_logql(rule)
    result.update(
        {
            "id": rule.get("id"),
            "title": rule.get("title"),
            "summary": rule.get("summary"),
            "grafana_url": grafana_explore_url(logql) if logql else None,
            "logql": logql,
        }
    )
    return result


def _parse_lookback(s: Any) -> int:
    if isinstance(s, (int, float)):
        return int(s)
    text = str(s).strip()
    m = re.match(r"^(\d+)(s|m|h)?$", text)
    if not m:
        return 180
    n = int(m.group(1))
    unit = m.group(2) or "s"
    return n * {"s": 1, "m": 60, "h": 3600}[unit]


def _default_logql(rule: dict[str, Any]) -> str:
    cfg = rule.get("eval") or {}
    route = cfg.get("route_contains") or "/siem-demo/"
    return f'{{log_source="http-log"}} |= "{route}"'


# --- attack runners ---


def run_001() -> dict[str, Any]:
    results = []
    for i in range(12):
        geo = random.choice(_ATTACK_GEO)
        code, _, body = proxy_get(
            f"/siem-demo/loan/customers/bad-{i}",
            headers={"apikey": f"wrong-key-{i}", "User-Agent": _BROWSER_UA},
            geo=geo,
        )
        results.append({"i": i, "status": code, "geo": geo})
    return {"rule": "KG-API-001", "requests": results}


def run_001b() -> dict[str, Any]:
    fails = []
    geo = random.choice(_ATTACK_GEO)
    for i in range(5):
        code, _, _ = proxy_get(
            "/siem-demo/loan/customers/probe",
            headers={"apikey": f"wrong-{i}", "User-Agent": _BROWSER_UA},
            geo=geo,
        )
        fails.append(code)
    ok, _, _ = proxy_get(
        "/siem-demo/loan/customers/1001",
        headers={"apikey": APIKEY, "User-Agent": _BROWSER_UA},
        geo=geo,
    )
    return {"rule": "KG-API-001b", "fail_statuses": fails, "success_status": ok, "geo": geo}


def run_002() -> dict[str, Any]:
    results = []
    geo = random.choice(_ATTACK_GEO)
    for i in range(1001, 1021):
        code, _, _ = proxy_get(
            f"/siem-demo/loan/customers/{i}",
            headers={"apikey": APIKEY, "User-Agent": _BROWSER_UA},
            geo=geo,
        )
        results.append({"id": i, "status": code, "geo": geo})
        if code == 429:
            break
        time.sleep(0.03)
    return {"rule": "KG-API-002", "requests": results}


def run_003() -> dict[str, Any]:
    results = []
    geo = random.choice(_ATTACK_GEO)
    for i in range(40):
        code, hdrs, _ = proxy_get(
            f"/siem-demo/loan/customers/rl-{i}",
            headers={"apikey": APIKEY, "User-Agent": _BROWSER_UA},
            geo=geo,
        )
        results.append(
            {
                "i": i,
                "status": code,
                "geo": geo,
                "ratelimit": {k: v for k, v in hdrs.items() if "rate" in k.lower() or "Limit" in k},
            }
        )
        if code == 429 and sum(1 for r in results if r["status"] == 429) >= 2:
            break
        time.sleep(0.03)
    return {"rule": "KG-API-003", "requests": results}


def run_004() -> dict[str, Any]:
    results = []
    for ua in ("python-requests/2.32.0", "curl/8.0", "siem-bot/1.0"):
        geo = random.choice(_ATTACK_GEO)
        code, _, _ = proxy_get(
            "/siem-demo/loan/customers/ua-demo",
            headers={"apikey": APIKEY, "User-Agent": ua},
            geo=geo,
        )
        results.append({"ua": ua, "status": code, "geo": geo})
    return {"rule": "KG-API-004", "requests": results}


def run_005() -> dict[str, Any]:
    results = []
    geo = random.choice(_ATTACK_GEO)
    for i in range(6):
        code, _, body = proxy_get(
            f"/siem-demo/loan/customers/{2000 + i}/bulk",
            headers={"apikey": APIKEY, "User-Agent": _BROWSER_UA},
            geo=geo,
        )
        results.append({"i": i, "status": code, "body_len": len(body), "geo": geo})
        time.sleep(0.05)
    return {"rule": "KG-API-005", "requests": results}


def run_006() -> dict[str, Any]:
    # No traffic — evaluation does Admin scan; optional GET to open route for visibility
    code, _, _ = proxy_get(
        "/siem-demo/loan/open/info",
        headers={"User-Agent": _BROWSER_UA},
        geo=random.choice(_ATTACK_GEO),
    )
    return {"rule": "KG-API-006", "open_status": code, "note": "evaluate performs Admin scan"}


def run_007() -> dict[str, Any]:
    a = run_001()
    time.sleep(0.5)
    b = run_005()
    return {"rule": "KG-API-007", "auth_burst": a, "exfil": b}


def run_008() -> dict[str, Any]:
    paths = [
        "/siem-demo/loan/customers/../open/info",
        "/siem-demo/loan/customers/%2e%2e/open/info",
        "/siem-demo/loan/customers/evil%2e%2e%2fsecret",
    ]
    results = []
    for p in paths:
        geo = random.choice(_ATTACK_GEO)
        code, _, _ = proxy_get(
            p,
            headers={"apikey": APIKEY, "User-Agent": _BROWSER_UA},
            geo=geo,
        )
        results.append({"path": p, "status": code, "geo": geo})
    return {"rule": "KG-API-008", "requests": results}


def run_009() -> dict[str, Any]:
    set_heartbeat(False)
    # Hold past min_silence_s so Evaluate can fire immediately after Run
    time.sleep(16)
    return {
        "rule": "KG-API-009",
        "heartbeat_enabled": False,
        "note": "heartbeat stopped for 16s; Evaluate should fire if proxy is up",
    }


def _mixed_one(kind: str, i: int) -> dict[str, Any]:
    """Single mixed-traffic step. 009 (silence) excluded — use dedicated Run."""
    if kind == "normal":
        cid = random.randint(3000, 3099)
        code, _, _ = proxy_get(
            f"/siem-demo/loan/customers/{cid}",
            headers={"apikey": APIKEY, "User-Agent": _BROWSER_UA},
            geo="kr",
        )
        return {"kind": kind, "rules": [], "path": f"/customers/{cid}", "status": code, "geo": "kr"}

    if kind == "normal_open_ok":
        geo = random.choice(_ATTACK_GEO)
        code, _, _ = proxy_get(
            "/siem-demo/loan/open/info",
            headers={"User-Agent": _BROWSER_UA},
            geo=geo,
        )
        return {"kind": kind, "rules": ["KG-API-006"], "path": "/open/info", "status": code, "geo": geo}

    if kind == "auth_fail":
        geo = random.choice(_ATTACK_GEO)
        code, _, _ = proxy_get(
            f"/siem-demo/loan/customers/mix-bad-{i}",
            headers={"apikey": f"wrong-mix-{i}-{random.randint(0, 9999)}", "User-Agent": _BROWSER_UA},
            geo=geo,
        )
        return {
            "kind": kind,
            "rules": ["KG-API-001", "KG-API-001b", "KG-API-007"],
            "status": code,
            "geo": geo,
        }

    if kind == "bola":
        geo = random.choice(_ATTACK_GEO)
        cid = random.randint(4000, 4099)
        code, _, _ = proxy_get(
            f"/siem-demo/loan/customers/{cid}",
            headers={"apikey": APIKEY, "User-Agent": _BROWSER_UA},
            geo=geo,
        )
        return {
            "kind": kind,
            "rules": ["KG-API-002", "KG-API-003"],
            "path": f"/customers/{cid}",
            "status": code,
            "geo": geo,
        }

    if kind == "script_ua":
        geo = random.choice(_ATTACK_GEO)
        ua = random.choice(["python-requests/2.32.0", "curl/8.0.1", "siem-bot/1.0"])
        code, _, _ = proxy_get(
            f"/siem-demo/loan/customers/ua-{i}",
            headers={"apikey": APIKEY, "User-Agent": ua},
            geo=geo,
        )
        return {"kind": kind, "rules": ["KG-API-004"], "ua": ua, "status": code, "geo": geo}

    if kind == "bulk":
        geo = random.choice(_ATTACK_GEO)
        cid = random.randint(5000, 5019)
        code, _, body = proxy_get(
            f"/siem-demo/loan/customers/{cid}/bulk",
            headers={"apikey": APIKEY, "User-Agent": _BROWSER_UA},
            geo=geo,
        )
        return {
            "kind": kind,
            "rules": ["KG-API-005", "KG-API-007"],
            "path": f"/customers/{cid}/bulk",
            "status": code,
            "body_len": len(body),
            "geo": geo,
        }

    if kind == "traversal":
        geo = random.choice(_ATTACK_GEO)
        path = random.choice(
            [
                "/siem-demo/loan/customers/../open/info",
                "/siem-demo/loan/customers/%2e%2e/open/info",
                "/siem-demo/loan/customers/evil%2e%2e%2fsecret",
            ]
        )
        code, _, _ = proxy_get(
            path,
            headers={"apikey": APIKEY, "User-Agent": _BROWSER_UA},
            geo=geo,
        )
        return {"kind": kind, "rules": ["KG-API-008"], "path": path, "status": code, "geo": geo}

    raise ValueError(kind)


def run_mixed(count: int = 40, attack_ratio: float = 0.45) -> dict[str, Any]:
    """Interleave benign customer reads with random attack scenarios."""
    count = max(5, min(int(count), 120))
    attack_ratio = max(0.0, min(float(attack_ratio), 0.9))
    attack_kinds = ["auth_fail", "bola", "script_ua", "bulk", "traversal", "normal_open_ok"]
    # Weighted: bola/auth more often so 001/002 fire in short demos
    attack_weights = [3, 3, 2, 2, 2, 1]

    steps: list[dict[str, Any]] = []
    kind_counts: dict[str, int] = {}
    for i in range(count):
        if random.random() >= attack_ratio:
            kind = "normal"
        else:
            kind = random.choices(attack_kinds, weights=attack_weights, k=1)[0]
        step = _mixed_one(kind, i)
        steps.append(step)
        kind_counts[kind] = kind_counts.get(kind, 0) + 1
        time.sleep(random.uniform(0.02, 0.08))

    # Optional fail→success nudge for 001b
    if kind_counts.get("auth_fail", 0) >= 2 and random.random() < 0.8:
        geo = random.choice(_ATTACK_GEO)
        code, _, _ = proxy_get(
            "/siem-demo/loan/customers/mix-success",
            headers={"apikey": APIKEY, "User-Agent": _BROWSER_UA},
            geo=geo,
        )
        steps.append(
            {
                "kind": "fail_then_success_tail",
                "rules": ["KG-API-001b"],
                "status": code,
                "geo": geo,
            }
        )
        kind_counts["fail_then_success_tail"] = 1

    return {
        "mode": "mixed",
        "count": len(steps),
        "attack_ratio": attack_ratio,
        "kind_counts": kind_counts,
        "note": (
            "009 silence not included. Geo on map uses demo headers "
            "(X-Demo-Lat/Lon/Country), not MaxMind — local Docker IPs have no public GeoIP."
        ),
        "steps": steps,
    }


RUNNERS = {
    "KG-API-001": run_001,
    "KG-API-001b": run_001b,
    "KG-API-002": run_002,
    "KG-API-003": run_003,
    "KG-API-004": run_004,
    "KG-API-005": run_005,
    "KG-API-006": run_006,
    "KG-API-007": run_007,
    "KG-API-008": run_008,
    "KG-API-009": run_009,
}


def set_heartbeat(enabled: bool) -> None:
    global _heartbeat_enabled, _heartbeat_stopped_at
    with _heartbeat_lock:
        _heartbeat_enabled = enabled
        if enabled:
            _heartbeat_stopped_at = None
        else:
            _heartbeat_stopped_at = time.time()


def heartbeat_loop() -> None:
    while True:
        with _heartbeat_lock:
            enabled = _heartbeat_enabled
        if enabled:
            code, _, _ = proxy_get("/siem-demo/heartbeat", headers={"User-Agent": _BROWSER_UA})
            with _heartbeat_lock:
                if 200 <= code < 300:
                    _heartbeat_stats["ok"] += 1
                else:
                    _heartbeat_stats["err"] += 1
                _heartbeat_stats["last"] = {"status": code, "ts": int(time.time())}
        time.sleep(5)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args) -> None:
        return

    def _send(self, code: int, body: Any, content_type: str = "application/json") -> None:
        if isinstance(body, (dict, list)):
            raw = _json_bytes(body)
            content_type = "application/json; charset=utf-8"
        elif isinstance(body, bytes):
            raw = body
        else:
            raw = str(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(raw)

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        if path == "/health":
            self._send(200, {"ok": True})
            return
        if path == "/api/rules":
            doc = load_rules()
            self._send(
                200,
                {
                    "rules": [
                        {
                            "id": r.get("id"),
                            "title": r.get("title"),
                            "summary": r.get("summary"),
                            "when": r.get("when"),
                            "kind": r.get("kind"),
                        }
                        for r in doc.get("rules") or []
                    ]
                },
            )
            return
        if path == "/api/heartbeat":
            with _heartbeat_lock:
                self._send(
                    200,
                    {"enabled": _heartbeat_enabled, "stats": dict(_heartbeat_stats)},
                )
            return
        if path in ("/", "/index.html"):
            self._file(STATIC / "index.html", "text/html; charset=utf-8")
            return
        if path.startswith("/static/"):
            rel = path[len("/static/") :]
            fp = STATIC / rel
            if fp.is_file():
                ctype = "text/css" if rel.endswith(".css") else "application/javascript"
                self._file(fp, ctype)
                return
        self._send(404, {"error": "not found"})

    def _file(self, fp: Path, ctype: str) -> None:
        raw = fp.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self) -> None:
        path = self.path.split("?", 1)[0]
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b"{}"
        try:
            payload = json.loads(raw.decode() or "{}")
        except json.JSONDecodeError:
            payload = {}

        if path == "/api/heartbeat":
            enabled = bool(payload.get("enabled", True))
            set_heartbeat(enabled)
            self._send(200, {"enabled": enabled})
            return

        m = re.match(r"^/api/run/([^/]+)$", path)
        if m:
            rid = m.group(1)
            fn = RUNNERS.get(rid)
            if not fn:
                self._send(404, {"error": f"unknown rule {rid}"})
                return
            try:
                result = fn()
                self._send(200, {"ok": True, "result": result})
            except Exception as e:  # noqa: BLE001
                self._send(500, {"ok": False, "error": str(e)})
            return

        m = re.match(r"^/api/evaluate/([^/]+)$", path)
        if m:
            rid = m.group(1)
            rule = rule_by_id(rid)
            if not rule:
                self._send(404, {"error": f"unknown rule {rid}"})
                return
            # allow settling for http-log → Loki
            time.sleep(float(payload.get("settle_s") or 2))
            try:
                result = evaluate_rule(rule)
                self._send(200, {"ok": True, "result": result})
            except Exception as e:  # noqa: BLE001
                self._send(500, {"ok": False, "error": str(e)})
            return

        if path == "/api/run-all":
            out = []
            for rid, fn in RUNNERS.items():
                if rid in ("KG-API-007", "KG-API-009"):
                    continue
                try:
                    out.append({"id": rid, "result": fn()})
                except Exception as e:  # noqa: BLE001
                    out.append({"id": rid, "error": str(e)})
            self._send(200, {"ok": True, "results": out})
            return

        if path == "/api/run-mixed":
            try:
                result = run_mixed(
                    count=int(payload.get("count") or 40),
                    attack_ratio=float(payload.get("attack_ratio") or 0.45),
                )
                self._send(200, {"ok": True, "result": result})
            except Exception as e:  # noqa: BLE001
                self._send(500, {"ok": False, "error": str(e)})
            return

        self._send(404, {"error": "not found"})


if __name__ == "__main__":
    t = threading.Thread(target=heartbeat_loop, name="heartbeat", daemon=True)
    t.start()
    print(f"SIEM demo UI on :{PORT} proxy={PROXY} loki={LOKI}", flush=True)
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
