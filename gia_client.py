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
"""

import os
import re
import time
import asyncio
import httpx

GIA_BASE_URL = os.getenv("GIA_BASE_URL", "https://gia-ai.gt-t.net/api/sam/diu")
GIA_API_KEY  = os.getenv("GIA_API_KEY", os.getenv("FBA_API_KEY", ""))
GIA_TIMEOUT  = float(os.getenv("GIA_TIMEOUT_SECONDS", "15"))
GIA_CACHE_TTL_S = float(os.getenv("GIA_CACHE_TTL_HOURS", "24")) * 3600

_HEADERS = {"X-API-Key": GIA_API_KEY} if GIA_API_KEY else {}

# In-memory cache: {normalized_platform: (result_dict | None, timestamp)}
_cache: dict[str, tuple[dict | None, float]] = {}
_cache_lock = asyncio.Lock()

# Vendor prefixes to strip when normalizing for fuzzy matching
_VENDOR_PREFIXES = [
    "fortinet", "cisco", "juniper", "palo alto", "checkpoint",
    "aruba", "hewlett packard", "hp ", "f5 ", "vmware", "citrix",
]


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
        if not component or not _component_matches(component, platform):
            continue
        recommended = (
            row.get("New Deployments")
            or row.get("new_deployments")
            or row.get("Recommended Version")
            or row.get("recommended_version")
            or ""
        )
        if not recommended or recommended.strip() == "N/A":
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
    try:
        resp = await client.get(
            f"{GIA_BASE_URL}/tables/{table_id}",
            headers=_HEADERS,
            timeout=GIA_TIMEOUT,
        )
        if resp.status_code != 200:
            return None
        body = resp.json()
        rows = (
            body.get("table_data_json", {}).get("rows")
            or body.get("rows")
            or []
        )
        return _extract_version_from_rows(rows, platform)
    except Exception:
        return None


async def _search_and_resolve(client: httpx.AsyncClient, platform: str) -> dict | None:
    """
    Search GIA for pages related to `platform`, then look up their tables.

    The search response shape is handled defensively — we look for table data
    embedded in results and also chase any table_id references we find.
    """
    try:
        resp = await client.get(
            f"{GIA_BASE_URL}/pages/search",
            params={"q": platform},
            headers=_HEADERS,
            timeout=GIA_TIMEOUT,
        )
        if resp.status_code != 200:
            return None
        body = resp.json()
    except Exception:
        return None

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

        # Inline table data embedded in search results
        rows = (
            item.get("table_data_json", {}).get("rows") if isinstance(item.get("table_data_json"), dict) else None
            or item.get("rows")
        )
        if isinstance(rows, list):
            inline_rows.extend(rows)

        # Explicit table_id on the item itself (e.g. search returned table chunks)
        table_id = item.get("table_id") or item.get("id")
        if isinstance(table_id, str) and re.match(r"\d+_\w+", table_id):
            table_ids_to_check.append(table_id)

        # List of table IDs referenced by a page
        for key in ("table_ids", "tables"):
            refs = item.get(key)
            if isinstance(refs, list):
                for ref in refs:
                    if isinstance(ref, str):
                        table_ids_to_check.append(ref)
                    elif isinstance(ref, dict) and ref.get("table_id"):
                        table_ids_to_check.append(ref["table_id"])

    # Try inline rows first (no extra HTTP round-trips)
    if inline_rows:
        result = _extract_version_from_rows(inline_rows, platform)
        if result:
            return result

    # Fetch referenced tables (deduplicated, up to 10)
    seen = set()
    unique_tables = [t for t in table_ids_to_check if not (t in seen or seen.add(t))]
    for table_id in unique_tables[:10]:
        result = await _fetch_table(client, table_id, platform)
        if result:
            return result

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
                return cached_result

    async with httpx.AsyncClient() as client:
        result = await _search_and_resolve(client, platform_name)

    async with _cache_lock:
        _cache[key] = (result, now)

    return result
