"""
GIA SAM/DIU API client — fetches engineering-recommended software versions
from GIA's internal knowledge base (Confluence-backed vector search).

API structure:
  GET /api/sam/diu/pages/search?q={term}   →  list of matching pages/chunks
  GET /api/sam/diu/tables/{table_id}       →  table rows with version data

Table rows contain:
  "Component"        — software name (e.g. "Fortinet Forti Manager")
  "New Deployments"  — engineering-recommended version for new installs
  "Current versions" — currently supported/accepted versions
  "End of Support"   — EoS date or "N/A"

Results are cached in memory per normalized platform name, TTL 24 hours.

Debug: set GIA_DEBUG=true to print full request/response details.
"""

import os
import re
import time
import asyncio
import httpx

GIA_BASE_URL    = os.getenv("GIA_BASE_URL", "https://gia-ai.gt-t.net/api/sam/diu")
GIA_API_KEY     = os.getenv("GIA_API_KEY", os.getenv("FBA_API_KEY", ""))
GIA_TIMEOUT     = float(os.getenv("GIA_TIMEOUT_SECONDS", "15"))
GIA_CACHE_TTL_S = float(os.getenv("GIA_CACHE_TTL_HOURS", "24")) * 3600
GIA_DEBUG       = os.getenv("GIA_DEBUG", "false").lower() in ("1", "true", "yes")

_HEADERS = {"X-API-Key": GIA_API_KEY} if GIA_API_KEY else {}

# In-memory cache: {normalized_platform: (result_dict | None, timestamp)}
_cache: dict[str, tuple[dict | None, float]] = {}
_cache_lock = asyncio.Lock()

# Vendor prefixes to strip when normalizing for fuzzy matching
_VENDOR_PREFIXES = [
    "fortinet", "cisco", "juniper", "palo alto", "checkpoint",
    "aruba", "hewlett packard", "hp ", "f5 ", "vmware", "citrix",
]


def _dbg(msg: str):
    if GIA_DEBUG:
        print(f"  [GIA] {msg}", flush=True)


def _normalize(name: str) -> str:
    """Lowercase, strip vendor prefix, collapse spaces and punctuation."""
    n = name.lower().strip()
    for prefix in _VENDOR_PREFIXES:
        if n.startswith(prefix):
            n = n[len(prefix):].strip()
            break
    return re.sub(r"[\s\-_/]+", "", n)


def _component_matches(component: str, platform: str) -> bool:
    """
    Return True if the GIA 'Component' column value is a plausible match
    for the NetBox platform name.

    Matching is bidirectional: either the normalized component contains the
    normalized platform or vice versa.  This handles cases like:
      NetBox "FortiManager" ↔ GIA "Fortinet Forti Manager"
      NetBox "FortiOS"      ↔ GIA "FortiOS"
    """
    nc = _normalize(component)
    np = _normalize(platform)
    if not nc or not np:
        return False
    return nc in np or np in nc


def _extract_version_from_rows(rows: list, platform: str) -> dict | None:
    """
    Scan table rows for a component matching `platform` and return version data.
    Returns None if no matching row is found.
    """
    for row in rows:
        component = str(row.get("Component") or row.get("component") or "")
        if not component:
            continue
        matches = _component_matches(component, platform)
        _dbg(f"  row component={component!r} norm={_normalize(component)!r} "
             f"vs platform norm={_normalize(platform)!r} → match={matches}")
        if not matches:
            continue
        recommended = (
            row.get("New Deployments")
            or row.get("new_deployments")
            or row.get("Recommended Version")
            or row.get("recommended_version")
            or ""
        )
        if not recommended or recommended.strip() == "N/A":
            _dbg(f"  matched component but recommended={recommended!r}, skipping")
            continue
        return {
            "gia_recommended_version": recommended.strip(),
            "gia_current_versions":    str(row.get("Current versions") or row.get("current_versions") or ""),
            "gia_end_of_support":      str(row.get("End of Support") or row.get("end_of_support") or "N/A"),
            "gia_component":           component,
        }
    return None


async def _fetch_table(client: httpx.AsyncClient, table_id: str, platform: str) -> dict | None:
    """Fetch a single table and scan its rows for a platform version match."""
    url = f"{GIA_BASE_URL}/tables/{table_id}"
    try:
        resp = await client.get(url, headers=_HEADERS, timeout=GIA_TIMEOUT)
        _dbg(f"  table {table_id} → HTTP {resp.status_code}")
        if resp.status_code != 200:
            return None
        body = resp.json()
        rows = (
            body.get("table_data_json", {}).get("rows")
            or body.get("rows")
            or []
        )
        _dbg(f"  table {table_id} has {len(rows)} row(s); keys={list(rows[0].keys()) if rows else []}")
        return _extract_version_from_rows(rows, platform)
    except Exception as e:
        _dbg(f"  table {table_id} fetch error: {e}")
        return None


async def _search_and_resolve(client: httpx.AsyncClient, platform: str) -> dict | None:
    """
    Search GIA for pages related to `platform`, then look up their tables.

    The search response shape is handled defensively — we look for table data
    embedded in results and also chase any table_id references we find.
    """
    url = f"{GIA_BASE_URL}/pages/search"
    _dbg(f"GET {url}?q={platform!r}  auth={'yes' if GIA_API_KEY else 'NO KEY SET'}")
    try:
        resp = await client.get(url, params={"q": platform}, headers=_HEADERS, timeout=GIA_TIMEOUT)
        _dbg(f"search → HTTP {resp.status_code}")
        if resp.status_code != 200:
            print(f"  [GIA] search HTTP {resp.status_code} for {platform!r}: {resp.text[:200]}", flush=True)
            return None
        body = resp.json()
    except Exception as e:
        print(f"  [GIA] search request failed for {platform!r}: {type(e).__name__}: {e!r}", flush=True)
        return None

    # Log the top-level shape so we can see what the API actually returns
    if isinstance(body, dict):
        _dbg(f"search response keys: {list(body.keys())}")
        for key in ("results", "items", "pages", "data", "hits"):
            if key in body:
                _dbg(f"  body[{key!r}] has {len(body[key])} item(s)")
    elif isinstance(body, list):
        _dbg(f"search response is a list of {len(body)} item(s)")
    else:
        _dbg(f"search response unexpected type: {type(body)}")

    # Always print a summary even without GIA_DEBUG so at least something shows up
    n_items = len(body) if isinstance(body, list) else len(body.get("results") or body.get("items") or body.get("data") or [])
    print(f"  [GIA] {platform!r}: search returned {n_items} result(s)", flush=True)

    # Normalize to a list of result items regardless of top-level wrapper
    items: list = []
    if isinstance(body, list):
        items = body
    elif isinstance(body, dict):
        for key in ("results", "items", "pages", "data", "hits"):
            if isinstance(body.get(key), list):
                items = body[key]
                break
        if not items and "id" in body:
            items = [body]

    table_ids_to_check: list[str] = []
    inline_rows: list = []

    for item in items:
        if not isinstance(item, dict):
            continue

        _dbg(f"  result item keys: {list(item.keys())}")

        # Inline table data embedded in search results
        tdata = item.get("table_data_json")
        rows = (tdata.get("rows") if isinstance(tdata, dict) else None) or item.get("rows")
        if isinstance(rows, list):
            _dbg(f"  found {len(rows)} inline rows")
            inline_rows.extend(rows)

        # Explicit table_id on the item itself (e.g. search returned table chunks)
        table_id = item.get("table_id") or item.get("id")
        if isinstance(table_id, str) and re.match(r"\d+_\w+", table_id):
            _dbg(f"  found table_id on item: {table_id}")
            table_ids_to_check.append(table_id)

        # List of table IDs referenced by a page
        for key in ("table_ids", "tables"):
            refs = item.get(key)
            if isinstance(refs, list):
                for ref in refs:
                    if isinstance(ref, str):
                        _dbg(f"  found table ref: {ref}")
                        table_ids_to_check.append(ref)
                    elif isinstance(ref, dict) and ref.get("table_id"):
                        _dbg(f"  found table ref dict: {ref['table_id']}")
                        table_ids_to_check.append(ref["table_id"])

    _dbg(f"inline_rows={len(inline_rows)}, table_ids={table_ids_to_check}")

    # Try inline rows first (no extra HTTP round-trips)
    if inline_rows:
        result = _extract_version_from_rows(inline_rows, platform)
        if result:
            return result

    # Fetch referenced tables (deduplicated, up to 10)
    seen: set = set()
    unique_tables = [t for t in table_ids_to_check if not (t in seen or seen.add(t))]
    if not unique_tables:
        print(f"  [GIA] {platform!r}: no table references found in search results "
              f"— response may use an unexpected structure. "
              f"Set GIA_DEBUG=true for full details.", flush=True)
    for table_id in unique_tables[:10]:
        result = await _fetch_table(client, table_id, platform)
        if result:
            return result

    print(f"  [GIA] {platform!r}: no version match found", flush=True)
    return None


async def lookup_platform_version(platform_name: str) -> dict | None:
    """
    Return engineering version data for `platform_name` from GIA, or None
    if no match is found.  Results are cached for GIA_CACHE_TTL_S seconds.

    Returned dict keys:
      gia_recommended_version  — version string for new deployments
      gia_current_versions     — comma-separated accepted versions
      gia_end_of_support       — EoS date string or "N/A"
      gia_component            — matched component name from GIA table
    """
    if not platform_name:
        return None

    key = _normalize(platform_name)
    now = time.monotonic()

    async with _cache_lock:
        if key in _cache:
            cached_result, cached_at = _cache[key]
            if now - cached_at < GIA_CACHE_TTL_S:
                _dbg(f"{platform_name!r}: returning cached result")
                return cached_result

    print(f"  [GIA] looking up {platform_name!r} (key={key!r}, api_key={'set' if GIA_API_KEY else 'NOT SET'})", flush=True)
    async with httpx.AsyncClient(verify=False, follow_redirects=True) as client:
        result = await _search_and_resolve(client, platform_name)

    if result:
        print(f"  [GIA] ✅ {platform_name!r} → {result['gia_recommended_version']} "
              f"(matched: {result['gia_component']!r})", flush=True)
    async with _cache_lock:
        _cache[key] = (result, now)

    return result
