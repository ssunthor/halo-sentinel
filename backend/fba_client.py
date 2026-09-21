"""
FBA (Firewall Baseline Analysis) API client.
Fetches device configuration analysis from the FBA API and caches results
in SQLite so the API is only hit when data is stale (>24h).

Lookup strategy per device:
  1. Direct GET /inventory/{name}.conf (exact, lowercase, uppercase variants)
  2. Fallback: GET /inventory?firewall={name} search, then fetch detail for each
     matching item — handles HA pairs where FBA appends -A/-B/-1/-2/-pri/-sec.
     Results from multiple nodes are merged (worst-case: vulnerable if any node is).
"""

import asyncio
import os
import httpx

FBA_BASE_URL = os.getenv("FBA_BASE_URL", "https://gia-ai.gt-t.net/api/fba")
FBA_API_KEY  = os.getenv("FBA_API_KEY",  "6PSYFpBW4Ax48V2CNpXuid1679tTtMKk")
FBA_TIMEOUT  = float(os.getenv("FBA_TIMEOUT_SECONDS", "15"))

# FBA's certificate is issued by the corporate CA (GICORP-ROOT-CA01), which is
# not in httpx's default (certifi) bundle. Set FBA_VERIFY_SSL to the CA bundle
# path (preferred) or "false". Same semantics as halo-backend's fba_sync.py.
_verify_env = os.getenv("FBA_VERIFY_SSL", "true").strip()
FBA_VERIFY_SSL = (False if _verify_env.lower() in ("false", "0", "no")
                  else True if _verify_env.lower() in ("true", "1", "yes", "")
                  else _verify_env)

# Most recent request failure, for the enrichment worker's log line. Lookups
# used to fail silently — a TLS or auth problem looked exactly like "FBA has no
# config for any device".
last_error: str | None = None


def _note_error(err) -> None:
    global last_error
    last_error = f"{type(err).__name__}: {err}"[:300] if isinstance(err, Exception) else str(err)[:300]

_HEADERS = {"X-API-Key": FBA_API_KEY}

# Returned in place of a data dict when the lookup could not be completed
# (timeout, connection error, 5xx). Distinct from None, which means FBA answered
# and holds no config for the device — callers must not cache this as "not found".
LOOKUP_FAILED = object()


def _name_variants(name: str) -> list:
    """Return name variants to try in order (exact → lowercase → uppercase)."""
    variants = [name]
    if name != name.lower():
        variants.append(name.lower())
    if name != name.upper():
        variants.append(name.upper())
    return variants


def _merge_results(details: list, filenames: list) -> dict:
    """
    Merge FBA results from multiple HA nodes into one device result.
    Vulnerability is worst-case (OR); analyzed is AND; error only if ALL errored.
    Findings and reason are combined with a per-node prefix.
    """
    merged = {
        "analyzed":      all(r.get("analyzed")      for r in details),
        "vulnerable":    any(r.get("vulnerable")     for r in details),
        "vuln_acl":      any(r.get("vuln_acl")       for r in details),
        "vuln_password": any(r.get("vuln_password")  for r in details),
        "error":         all(r.get("error")           for r in details),
        "findings":      [],
        "reason":        "",
        # Config-aware CVE analysis reads one node's config; HA peers share theirs.
        "config_url":    next((r.get("config_url") for r in details if r.get("config_url")), None),
    }

    reasons = []
    for result, fname in zip(details, filenames):
        node = fname.replace(".conf", "")
        if result.get("reason"):
            reasons.append(f"[{node}] {result['reason']}")
        for finding in result.get("findings") or []:
            merged["findings"].append({**finding, "node": node})

    merged["reason"] = " | ".join(reasons)
    return merged


async def _fetch_one(
    client: httpx.AsyncClient,
    device_name: str,
    semaphore: asyncio.Semaphore,
) -> tuple:
    """
    Resolve a NetBox device name to FBA data.
    Returns (device_name, data_dict | None | LOOKUP_FAILED).
    """
    failed = False   # any request errored → a miss is not a trustworthy "not found"
    async with semaphore:
        # ── 1. Direct lookup (fast path) ──────────────────────────────────
        for name in _name_variants(device_name):
            url = f"{FBA_BASE_URL}/inventory/{name}.conf"
            try:
                resp = await client.get(url, headers=_HEADERS, timeout=FBA_TIMEOUT)
                if resp.status_code == 200:
                    body = resp.json()
                    if body.get("success") and body.get("data"):
                        return device_name, body["data"]
                elif resp.status_code != 404:
                    failed = True
                    _note_error(f"HTTP {resp.status_code} from {url}")
            except Exception as e:
                failed = True
                _note_error(e)

        # ── 2. Search fallback (handles HA suffixes: -A/-B, -1/-2, -pri/-sec) ──
        for query in _name_variants(device_name):
            try:
                resp = await client.get(
                    f"{FBA_BASE_URL}/inventory",
                    params={"firewall": query},
                    headers=_HEADERS,
                    timeout=FBA_TIMEOUT,
                )
                if resp.status_code != 200:
                    failed = True
                    _note_error(f"HTTP {resp.status_code} from inventory search")
                    continue
                body = resp.json()
                items = body.get("data", {}).get("items") or []

                # Only accept items whose filename actually starts with our query
                # (prevents false positives if the API does fuzzy matching)
                q_upper = query.upper()
                items = [
                    i for i in items
                    if i.get("filename", "").upper().startswith(q_upper)
                ]
                if not items:
                    continue

                # Fetch full details for each matching node (sequential, within semaphore)
                details = []
                filenames = []
                for item in items:
                    detail_url = item.get("url")
                    if not detail_url:
                        continue
                    try:
                        dr = await client.get(detail_url, headers=_HEADERS, timeout=FBA_TIMEOUT)
                        if dr.status_code == 200:
                            db = dr.json()
                            if db.get("success") and db.get("data"):
                                details.append(db["data"])
                                filenames.append(item.get("filename", ""))
                        else:
                            failed = True
                            _note_error(f"HTTP {dr.status_code} from {detail_url}")
                    except Exception as e:
                        failed = True
                        _note_error(e)

                if not details:
                    continue

                if len(details) == 1:
                    return device_name, details[0]
                return device_name, _merge_results(details, filenames)

            except Exception as e:
                failed = True
                _note_error(e)

    return device_name, (LOOKUP_FAILED if failed else None)


async def fetch_configs_chunk(
    device_names: list,
    concurrency: int = 20,
) -> dict:
    """
    Fetch FBA config data for a chunk of device names.
    Returns {device_name: data_dict | None | LOOKUP_FAILED} — None means FBA holds
    no config for the device; LOOKUP_FAILED means we could not find out.
    """
    semaphore = asyncio.Semaphore(concurrency)
    results = {}

    async with httpx.AsyncClient(verify=FBA_VERIFY_SSL) as client:
        tasks = [_fetch_one(client, name, semaphore) for name in device_names]
        for coro in asyncio.as_completed(tasks):
            name, data = await coro
            results[name] = data

    return results


async def fetch_raw_config(config_url: str) -> str | None:
    """
    Fetch a device's full raw configuration from FBA (GET /config/<filename>).
    Returns the config text, or None if unavailable. The URL comes from an FBA
    API response, so it is only followed when it points back at FBA_BASE_URL.
    The text contains secrets — callers must redact before storing or prompting.
    """
    if not config_url or not config_url.startswith(FBA_BASE_URL.rstrip("/") + "/"):
        return None
    try:
        async with httpx.AsyncClient(verify=FBA_VERIFY_SSL) as client:
            resp = await client.get(config_url, headers=_HEADERS, timeout=max(FBA_TIMEOUT, 60))
        if resp.status_code != 200:
            _note_error(f"HTTP {resp.status_code} from {config_url}")
            return None
        body = resp.json()
        raw = (body.get("data") or {}).get("raw_config") if body.get("success") else None
        return raw if isinstance(raw, str) and raw.strip() else None
    except Exception as e:
        _note_error(e)
        return None
