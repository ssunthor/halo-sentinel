"""
GIA SAM/DIU client — GTT Engineering's approved software versions.

Engineering publishes the versions approved for production on the Confluence
page "SD-WAN Software Version Control" (space UW, page 6848998). SERA's Data
Inspector Utility (DIU, sera/admin-suite/data-inspector-utility) indexes that
page and GIA fronts the DIU gRPC service over REST (GIA_API_URL + /sam/diu;
the same root that serves FBA under /fba):

  GET /api/sam/diu/pages/search?query=<page title>&search_text=<text>&expand=true
      GetPagesByTitle: pages whose title matches `query`, restricted to the
      chunks (Confluence sections) that contain `search_text`; `expand=true`
      also returns each matched chunk's sub-sections. Response:
        {"pages": [{"metadata": {...}, "chunks": [
            {"header_text": "...", "structured_tables_json": {
                "<table_id>": {"headers": [...], "rows": [{col: val}]}}}]}]}
      (`structured_tables_json` may also arrive as a JSON string.)

  GET /api/sam/diu/tables/<table_id>
      LookupTable: one table by id, e.g. 6848998_SEC_42_TABLE_1 →
        {"table_id", "page_id", "page_title", "chunk_header_text",
         "table_data_json": {"headers": [...], "rows": [...]}, "table_summary"}

Under the section "Fortinet Edges, Gateways, and Central Management Devices"
the "Approved versions" chunk carries two tables: the live one, whose columns
are Component / Current Used Versions / New Deployments / GTT Preferred
Version / Approved Date / PV End of Support / Future Release*, and an older
one with only Component / Current versions / New Deployments / End of
Support. Rows are per product role ("Fortigate SD WAN Edge", "Fortigate SD
WAN Gateway", "FortiSwitch (FortiLink)", "FortiManager (Physical or VM)" …),
not per NetBox platform, so a device is mapped to a row from its platform,
model family and NetBox role (see classify_device).

The page is searched first so the lookup survives re-ingestion (table ids
embed the chunk sequence number); GIA_TABLE_IDS is the fallback when the
search finds no tables. The chosen table is cached in memory for
GIA_CACHE_TTL_HOURS (default 24) — one or two requests a day for the whole
estate. All requests carry the same X-API-Key as the FBA client.

Debug: GIA_DEBUG=true logs every request and every device → row decision.
"""

import asyncio
import json
import os
import re
import time
from collections import Counter

import httpx

import cve_matching
import fba_client

# Root shared with FBA (fba_client.GIA_API_URL); GIA_DIU_URL overrides just this service.
GIA_BASE_URL     = os.getenv("GIA_DIU_URL", f"{fba_client.GIA_API_URL}/sam/diu").rstrip("/")
GIA_API_KEY      = os.getenv("GIA_API_KEY") or fba_client.FBA_API_KEY
GIA_TIMEOUT      = float(os.getenv("GIA_TIMEOUT_SECONDS", "20"))
GIA_CACHE_TTL_S  = float(os.getenv("GIA_CACHE_TTL_HOURS", "24")) * 3600
GIA_RETRY_S      = float(os.getenv("GIA_RETRY_MINUTES", "10")) * 60   # after a failed load
GIA_DEBUG        = os.getenv("GIA_DEBUG", "false").lower() in ("1", "true", "yes")
GIA_PAGE_QUERY   = os.getenv("GIA_PAGE_QUERY", "SD-WAN Software Version Control")
GIA_SECTION_TEXT = os.getenv("GIA_SECTION_TEXT", "Fortinet Edges, Gateways, and Central Management Devices")
GIA_TABLE_IDS    = [t.strip() for t in os.getenv(
    "GIA_TABLE_IDS", "6848998_SEC_42_TABLE_1,6848998_SEC_42_TABLE_2").split(",") if t.strip()]

# Same corporate CA as FBA (both live on the same GIA host); GIA_VERIFY_SSL
# overrides FBA_VERIFY_SSL with the same semantics (CA bundle path / false).
_verify_env = os.getenv("GIA_VERIFY_SSL", "").strip()
GIA_VERIFY_SSL = (fba_client.FBA_VERIFY_SSL if not _verify_env
                  else False if _verify_env.lower() in ("false", "0", "no")
                  else True if _verify_env.lower() in ("true", "1", "yes")
                  else _verify_env)

_HEADERS = {"X-API-Key": GIA_API_KEY} if GIA_API_KEY else {}

# ---------------------------------------------------------------------------
# Module state: the one cached table + observability
# ---------------------------------------------------------------------------

_table: dict | None = None          # see _build_table()
_table_loaded_at: float = 0.0       # monotonic
_load_failed_at: float = 0.0        # monotonic
_load_lock = asyncio.Lock()

stats = {
    "requests": 0,
    "http_2xx": 0,
    "http_other": 0,
    "exceptions": 0,
    "last_error": None,
    "last_error_at": None,
    "last_ok_at": None,
    # device decisions since process start
    "devices_checked": 0,
    "non_fortinet": 0,
    "no_row": 0,
    "upgrade_needed": 0,
    "compliant": 0,
    "components": Counter(),
}


def _dbg(msg: str) -> None:
    if GIA_DEBUG:
        print(f"  [GIA] {msg}", flush=True)


def _note_error(err) -> None:
    stats["last_error"] = (f"{type(err).__name__}: {err}" if isinstance(err, Exception) else str(err))[:300]
    stats["last_error_at"] = time.time()


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

async def _get(client: httpx.AsyncClient, url: str, params: dict | None = None):
    """GET → parsed JSON body, or None on any failure (recorded in stats)."""
    stats["requests"] += 1
    t0 = time.time()
    shown = url.replace(GIA_BASE_URL, "") + (
        "?" + "&".join(f"{k}={v}" for k, v in params.items()) if params else "")
    try:
        resp = await client.get(url, params=params, headers=_HEADERS, timeout=GIA_TIMEOUT)
    except Exception as e:
        stats["exceptions"] += 1
        _note_error(e)
        print(f"  [GIA] GET {shown} → {type(e).__name__}: {str(e)[:160]}", flush=True)
        return None
    ms = (time.time() - t0) * 1000
    if 200 <= resp.status_code < 300:
        stats["http_2xx"] += 1
        stats["last_ok_at"] = time.time()
        _dbg(f"GET {shown} → HTTP {resp.status_code} ({ms:.0f}ms, {len(resp.content)} bytes)")
        try:
            return resp.json()
        except Exception as e:
            _note_error(e)
            print(f"  [GIA] GET {shown} → invalid JSON: {e}", flush=True)
            return None
    stats["http_other"] += 1
    _note_error(f"HTTP {resp.status_code} from {shown}: {resp.text[:120]}")
    print(f"  [GIA] GET {shown} → HTTP {resp.status_code} ({ms:.0f}ms): {resp.text[:120]}", flush=True)
    return None


# ---------------------------------------------------------------------------
# Table parsing (pure functions, unit-tested)
# ---------------------------------------------------------------------------

def _squash(s) -> str:
    return re.sub(r"[^a-z0-9]", "", str(s or "").lower())


def _col(row: dict, *names: str) -> str:
    """First non-empty cell whose header matches one of `names` (case/space-insensitive)."""
    want = [_squash(n) for n in names]
    by_key = {_squash(k): v for k, v in row.items()}
    for w in want:
        v = by_key.get(w)
        if v is not None and str(v).strip():
            return str(v).strip()
    return ""


def _versions_in(text: str) -> list[str]:
    return re.findall(r"\d+(?:\.\d+)+", text or "")


def _parse_date(text: str) -> tuple:
    """'4.8.2026' / '11.15.2027' / '2026-04-08' → sortable (y, m, d); () if unknown."""
    m = re.search(r"(\d{1,2})[./-](\d{1,2})[./-](\d{4})", text or "")
    if m:
        return (int(m.group(3)), int(m.group(1)), int(m.group(2)))
    m = re.search(r"(\d{4})-(\d{1,2})-(\d{1,2})", text or "")
    if m:
        return (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    return ()


def _split_merged_row(component: str, preferred: str) -> list[tuple[str, str]]:
    """Confluence sometimes flattens several rows into one cell:
    'FortiAP 221E (FortiLink)FortiAP 231F (FortiLink)…' with the versions run
    together as '7.4.57.4.67.4.6…'. Split them back apart when the pieces line
    up; otherwise return the row unchanged."""
    parts = re.findall(r"Forti\w+[^()]*?\([^)]*\)", component or "")
    if len(parts) < 2:
        return [(component, preferred)]
    pattern = "^" + "".join(r"(\d+\.\d+\.\d+?)" for _ in parts) + "$"
    m = re.match(pattern, (preferred or "").replace(" ", ""))
    if not m:
        return [(component, preferred)]
    return list(zip((p.strip() for p in parts), m.groups()))


def parse_rows(raw_rows: list) -> list[dict]:
    """Normalise table rows into component records.

    Each record: component, preferred (the GTT Preferred Version, else New
    Deployments), preferred_version (highest x.y.z in it, or None),
    current_versions, new_deployments, future_release, end_of_support,
    approved_date, approved (sortable tuple), key (squashed component)."""
    out = []
    for row in raw_rows or []:
        if not isinstance(row, dict):
            continue
        component = _col(row, "Component")
        if not component:
            continue
        preferred = _col(row, "GTT Preferred Version", "New Deployments", "Recommended Version")
        approved_date = _col(row, "Approved Date")
        for comp, pref in _split_merged_row(component, preferred):
            versions = _versions_in(pref)
            out.append({
                "component":         comp,
                "key":               _squash(comp),
                "preferred":         pref,
                "preferred_version": max(versions, key=cve_matching.version_key) if versions else None,
                "new_deployments":   _col(row, "New Deployments"),
                "current_versions":  _col(row, "Current Used Versions", "Current versions"),
                "future_release":    _col(row, "Future Release*", "Future Release"),
                "end_of_support":    _col(row, "PV End of Support", "End of Support") or "N/A",
                "approved_date":     approved_date,
                "approved":          _parse_date(approved_date),
            })
    return out


def _table_score(table: dict) -> tuple:
    """Rank candidate tables: the live one has a GTT Preferred Version column
    and the most recent Approved Date; row count breaks ties."""
    headers = {_squash(h) for h in table.get("headers") or []}
    if not headers and table.get("rows"):
        headers = {_squash(k) for k in table["rows"][0].keys()}
    has_preferred = "gttpreferredversion" in headers
    latest = max((r["approved"] for r in table.get("parsed") or []), default=())
    return (has_preferred, latest, len(table.get("parsed") or []))


def _build_table(table_id: str, data: dict, *, source: str, page_title: str = "", chunk_header: str = "") -> dict | None:
    """One candidate table from a DIU `table_data_json`-shaped dict."""
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except Exception:
            return None
    if not isinstance(data, dict):
        return None
    rows = data.get("rows")
    if not isinstance(rows, list) or not rows:
        return None
    table = {
        "table_id":     table_id,
        "source":       source,
        "page_title":   page_title,
        "chunk_header": chunk_header,
        "headers":      data.get("headers") or list(rows[0].keys()),
        "parsed":       parse_rows(rows),
    }
    return table if table["parsed"] else None


def tables_from_search(body) -> list[dict]:
    """Every structured table in a /pages/search response."""
    found = []
    pages = body.get("pages") if isinstance(body, dict) else body
    for page in pages or []:
        if not isinstance(page, dict):
            continue
        title = ((page.get("metadata") or {}).get("title")) or ""
        for chunk in page.get("chunks") or []:
            if not isinstance(chunk, dict):
                continue
            tables = chunk.get("structured_tables_json")
            if isinstance(tables, str):
                try:
                    tables = json.loads(tables)
                except Exception:
                    tables = None
            if not isinstance(tables, dict):
                continue
            for tid, data in tables.items():
                t = _build_table(tid, data, source="search", page_title=title,
                                 chunk_header=chunk.get("header_text") or "")
                if t:
                    found.append(t)
    return found


def table_from_lookup(body) -> dict | None:
    """The table in a /tables/<id> response."""
    if not isinstance(body, dict):
        return None
    return _build_table(body.get("table_id") or "", body.get("table_data_json"), source="table_id",
                        page_title=body.get("page_title") or "",
                        chunk_header=body.get("chunk_header_text") or "")


def pick_table(candidates: list[dict]) -> dict | None:
    return max(candidates, key=_table_score) if candidates else None


# ---------------------------------------------------------------------------
# Device → component row
# ---------------------------------------------------------------------------

_FORTINET_HINT = re.compile(r"forti|fortinet|\bfgt\b|\bfsw\b|\bfmg\b|\bfaz\b", re.I)


def is_fortinet(platform: str | None, model: str | None = None, role: str | None = None) -> bool:
    return bool(_FORTINET_HINT.search(" ".join(str(x or "") for x in (platform, model, role))))


def classify_device(platform: str | None, model: str | None = None, role: str | None = None,
                    category: str | None = None) -> list[str]:
    """Ordered regexes (over the squashed component name) for the engineering
    rows this device could belong to; [] when it is not a Fortinet product we
    have a row for. First regex that hits a row wins, so the most specific
    reading comes first and a generic one last.

    NetBox reality (Sept 2026): 10.6k FortiOS devices, almost all with the
    generic role "CPE", models FortiGate-<n><series>, FortiWiFi-…,
    FortiGate-VM64(-KVM/-AWS/-AZURE) and FortiSwitch-1xx<series>; the few
    FortiManager / FortiAnalyzer / gateway / NFV instances are told apart by
    platform ("FortiManager 6.x") or role ("NFV Fortigate", "Fortinet
    Central Gateway"). A physical FortiGate CPE cannot be told SD-WAN from
    non-SD-WAN edge, so it defaults to "Fortigate SD WAN Edge" (GTT's
    Fortinet CPE product) with the non-SD-WAN row of its hardware series as
    the fallback."""
    if not is_fortinet(platform, model, role):
        return []
    p, m, r = _squash(platform), _squash(model), _squash(role)
    everything = p + " " + m + " " + r
    is_vm = (category == "vm") or bool(re.search(r"vm\d*(kvm|aws|azure|gcp)?\b", m or "")) or "vm" in p

    if "fortimanager" in everything or re.search(r"\bfmg\b", str(role or "") + " " + str(model or ""), re.I):
        return [r"fortimanager"]
    if "fortianalyzer" in everything or re.search(r"\bfaz\b", str(role or "") + " " + str(model or ""), re.I):
        return [r"fortianalyzer"]
    if "forticlient" in everything or "ems" == r:
        return []
    if "fortiswitch" in everything or re.search(r"\bfsw\b", str(role or "") + " " + str(model or ""), re.I):
        if "nid" in r or "monitoring" in r:
            return [r"fortiswitch.*nid", r"fortiswitch"]
        return [r"fortiswitch.*fortilink", r"^fortiswitch(?!.*nid)", r"fortiswitch"]
    if "fortiap" in everything:
        num = re.search(r"(\d{3}[a-z])", m)
        return ([rf"fortiap{num.group(1)}"] if num else []) + [r"fortiap"]

    # FortiGate / FortiWiFi / FortiOS
    out = []
    if "gateway" in r or re.search(r"\bgw\b", str(role or ""), re.I):
        out.append(r"fortigatesdwangateway")
    if re.search(r"\bsse\b", str(role or ""), re.I):
        out.append(r"fortigatessenode")
    if "nfv" in r:
        out.append(r"fortigatevmonnfvpod")
    if is_vm:
        out.append(r"^fortigatesdwanedgevm$")
        out.append(r"fortigatevmonnfvpod")
    series = re.search(r"\d+([a-z])[a-z]*$", m.replace("3g4g", "").replace("nam", ""))
    out.append(r"^fortigatesdwanedge$")
    if series:
        out.append(rf"fortigateedgenonsdwan.*{series.group(1)}series")
    out.append(r"fortigateedgenonsdwan")
    out.append(r"fortigatesdwanedge")
    return out


def match_row(rows: list[dict], candidates: list[str]) -> dict | None:
    for pattern in candidates:
        rx = re.compile(pattern)
        for row in rows:
            if rx.search(row["key"]):
                return row
    return None


def recommend(platform: str | None, os_version: str | None, model: str | None = None,
              role: str | None = None, category: str | None = None,
              table: dict | None = None) -> dict | None:
    """Engineering recommendation for one device from the cached table.

    Returns None when the device is not Fortinet, no row matches, or the row
    carries no parsable version. Otherwise:
      gia_recommended_version  — GTT Preferred Version (e.g. "7.4.11")
      gia_component            — the engineering row it came from
      gia_upgrade_needed       — device version < preferred (or unknown)
      gia_device_version       — x.y.z parsed from os_version, or None
      gia_current_versions / gia_end_of_support / gia_approved_date
    """
    table = table if table is not None else _table
    stats["devices_checked"] += 1
    candidates = classify_device(platform, model, role, category)
    if not candidates:
        stats["non_fortinet"] += 1
        return None
    if not table:
        return None
    row = match_row(table["parsed"], candidates)
    if not row or not row["preferred_version"]:
        stats["no_row"] += 1
        _dbg(f"no engineering row for platform={platform!r} model={model!r} role={role!r} "
             f"(tried {candidates})")
        return None
    dev_ver = cve_matching.device_version(os_version)
    needed = (dev_ver is None or
              cve_matching._cmp(cve_matching.version_key(dev_ver),
                                cve_matching.version_key(row["preferred_version"])) < 0)
    stats["upgrade_needed" if needed else "compliant"] += 1
    stats["components"][row["component"]] += 1
    _dbg(f"{platform!r}/{model!r}/{role!r} {os_version!r} → {row['component']!r} "
         f"{row['preferred_version']} upgrade_needed={needed}")
    return {
        "gia_recommended_version": row["preferred_version"],
        "gia_component":           row["component"],
        "gia_upgrade_needed":      needed,
        "gia_device_version":      dev_ver,
        "gia_current_versions":    row["current_versions"],
        "gia_end_of_support":      row["end_of_support"],
        "gia_approved_date":       row["approved_date"],
    }


def netbox_fields(resource: dict, resource_type: str) -> dict:
    """The recommend() inputs for a raw NetBox device / VM dict."""
    platform = (resource.get("platform") or {}).get("name")
    role = ((resource.get("role") or resource.get("device_role") or {}).get("name"))
    if resource_type == "vm":
        model = (resource.get("cluster") or {}).get("name")
        os_version = (resource.get("custom_fields") or {}).get("os_version")
    else:
        model = (resource.get("device_type") or {}).get("model")
        os_version = (resource.get("custom_fields") or {}).get("os_build")
    return {"platform": platform, "os_version": os_version, "model": model,
            "role": role, "category": resource_type}


def recommend_for_netbox(resource: dict, resource_type: str) -> dict | None:
    """recommend() for a raw NetBox dict, using the already-loaded table."""
    return recommend(**netbox_fields(resource, resource_type))


def upgrade_fields(rec: dict | None) -> dict:
    """The two persisted columns. Set only when the device is behind the
    engineering standard — a compliant device shows nothing."""
    if rec and rec.get("gia_upgrade_needed"):
        return {"gia_recommended_version": rec["gia_recommended_version"],
                "gia_component": rec["gia_component"]}
    return {"gia_recommended_version": None, "gia_component": None}


# ---------------------------------------------------------------------------
# Loading / caching
# ---------------------------------------------------------------------------

async def _fetch_table(client: httpx.AsyncClient) -> dict | None:
    """Search the page for the Fortinet section's tables; fall back to the
    configured table ids. Returns the best candidate or None."""
    candidates: list[dict] = []
    body = await _get(client, f"{GIA_BASE_URL}/pages/search", {
        "query": GIA_PAGE_QUERY, "search_text": GIA_SECTION_TEXT, "expand": "true",
    })
    if body is not None:
        candidates = tables_from_search(body)
        _dbg(f"search found {len(candidates)} table(s): {[t['table_id'] for t in candidates]}")
    if not candidates:
        print(f"  [GIA] page search returned no tables — falling back to GIA_TABLE_IDS "
              f"{GIA_TABLE_IDS}", flush=True)
        for tid in GIA_TABLE_IDS:
            body = await _get(client, f"{GIA_BASE_URL}/tables/{tid}")
            t = table_from_lookup(body)
            if t:
                candidates.append(t)
    return pick_table(candidates)


async def ensure_table(force: bool = False) -> dict | None:
    """Load (or refresh) the engineering table. Cheap when cached; a failed
    load is not retried for GIA_RETRY_MINUTES so scans never stall on GIA."""
    global _table, _table_loaded_at, _load_failed_at
    now = time.monotonic()
    if not force and _table and now - _table_loaded_at < GIA_CACHE_TTL_S:
        return _table
    if not force and not _table and _load_failed_at and now - _load_failed_at < GIA_RETRY_S:
        return None
    async with _load_lock:
        now = time.monotonic()
        if not force and _table and now - _table_loaded_at < GIA_CACHE_TTL_S:
            return _table
        print(f"  [GIA] loading engineering versions from {GIA_BASE_URL} "
              f"(api_key={'set' if GIA_API_KEY else 'NOT SET'})", flush=True)
        try:
            async with httpx.AsyncClient(verify=GIA_VERIFY_SSL, follow_redirects=True) as client:
                table = await _fetch_table(client)
        except Exception as e:
            _note_error(e)
            table = None
        if table:
            _table, _table_loaded_at = table, time.monotonic()
            _load_failed_at = 0.0
            rows = table["parsed"]
            print(f"  [GIA] ✅ {table['table_id']} ({table['source']}, {len(rows)} rows, "
                  f"latest approval {max((r['approved_date'] for r in rows if r['approved']), default='n/a')}): "
                  + ", ".join(f"{r['component']}={r['preferred_version']}" for r in rows[:6])
                  + (" …" if len(rows) > 6 else ""), flush=True)
        else:
            _load_failed_at = time.monotonic()
            print(f"  [GIA] ❌ could not load the engineering versions table "
                  f"({stats['last_error'] or 'no tables found'}); "
                  f"{'keeping the stale copy' if _table else 'no recommendations this cycle'}", flush=True)
    return _table


async def lookup_device(platform: str | None, os_version: str | None, model: str | None = None,
                        role: str | None = None, category: str | None = None) -> dict | None:
    """recommend() after making sure the table is loaded. Non-Fortinet devices
    never trigger a load."""
    if not classify_device(platform, model, role, category):
        stats["devices_checked"] += 1
        stats["non_fortinet"] += 1
        return None
    table = await ensure_table()
    return recommend(platform, os_version, model, role, category, table=table)


async def lookup_netbox(resource: dict, resource_type: str) -> dict | None:
    return await lookup_device(**netbox_fields(resource, resource_type))


def status() -> dict:
    """For GET /api/gia/status."""
    now = time.monotonic()
    t = _table
    return {
        "base_url": GIA_BASE_URL,
        "api_key_set": bool(GIA_API_KEY),
        "verify_ssl": GIA_VERIFY_SSL,
        "page_query": GIA_PAGE_QUERY,
        "section_text": GIA_SECTION_TEXT,
        "fallback_table_ids": GIA_TABLE_IDS,
        "cache_ttl_hours": GIA_CACHE_TTL_S / 3600,
        "table": None if not t else {
            "table_id": t["table_id"],
            "source": t["source"],
            "page_title": t["page_title"],
            "chunk_header": t["chunk_header"],
            "headers": t["headers"],
            "loaded_seconds_ago": int(now - _table_loaded_at),
            "stale": now - _table_loaded_at >= GIA_CACHE_TTL_S,
            "rows": [{
                "component": r["component"],
                "recommended_version": r["preferred_version"],
                "preferred_raw": r["preferred"],
                "current_versions": r["current_versions"],
                "end_of_support": r["end_of_support"],
                "approved_date": r["approved_date"],
            } for r in t["parsed"]],
        },
        "last_load_failed_seconds_ago": int(now - _load_failed_at) if _load_failed_at else None,
        "stats": {**{k: v for k, v in stats.items() if k != "components"},
                  "components": dict(stats["components"])},
    }
