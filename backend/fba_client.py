"""
FBA (Firewall Baseline Analysis) API client.
Fetches device configuration analysis from the FBA API and caches results
in SQLite so the API is only hit when data is stale (>24h).

Lookup strategy per device (at most 2 requests for a miss):
  1. Direct GET /inventory/{name}.conf — exact name only (this endpoint is
     case-sensitive, but FBA files are named after the NetBox device name).
  2. Fallback: one GET /inventory?firewall={name} search (case-insensitive on
     FBA's side), then fetch detail for each matching item — handles HA pairs
     where FBA appends -A/-B/-1/-2/-pri/-sec and any name-case drift. Results
     from multiple nodes are merged (worst-case: vulnerable if any node is).

All requests go through one global rate limiter (FBA_RATE_LIMIT requests per
second, default 5) so the enrichment run cannot flood the GIA API.
"""

import asyncio
import os
import time
import httpx

FBA_BASE_URL = os.getenv("FBA_BASE_URL", "https://gia-ai.gt-t.net/api/fba")
FBA_API_KEY  = os.getenv("FBA_API_KEY",  "6PSYFpBW4Ax48V2CNpXuid1679tTtMKk")
FBA_TIMEOUT  = float(os.getenv("FBA_TIMEOUT_SECONDS", "15"))
FBA_RATE_LIMIT = float(os.getenv("FBA_RATE_LIMIT", "5"))   # requests per second, all lookups combined

if not os.getenv("FBA_API_KEY"):
    print("⚠️  FBA_API_KEY is not set — using the key baked into fba_client.py. "
          "Set it in the environment and rotate the baked-in key.")

# FBA's certificate is issued by the corporate CA (GICORP-ROOT-CA01), which is
# not in httpx's default (certifi) bundle. Set FBA_VERIFY_SSL to the CA bundle
# path (preferred) or "false". Same semantics as halo-backend's fba_sync.py.
_verify_env = os.getenv("FBA_VERIFY_SSL", "true").strip()
FBA_VERIFY_SSL = (False if _verify_env.lower() in ("false", "0", "no")
                  else True if _verify_env.lower() in ("true", "1", "yes", "")
                  else _verify_env)

# FBA_DEBUG=true logs every request to FBA (method, URL, status or exception,
# latency) — the way to see what is actually happening on the GIA API.
FBA_DEBUG = os.getenv("FBA_DEBUG", "false").lower() in ("1", "true", "yes")

# Live counters for every request made to FBA, exposed by
# GET /api/config-applicability/status. Lookups used to fail silently — a TLS
# or auth problem looked exactly like "FBA has no config for any device".
stats = {
    "requests": 0,
    "http_2xx": 0,
    "http_404": 0,
    "http_other": 0,
    "exceptions": 0,
    "last_error": None,
    "last_error_at": None,
    "last_ok_at": None,
}
# The enrichment worker's current run (done/total/found/not_found/failed).
progress: dict = {}
last_error: str | None = None   # kept as an alias of stats["last_error"]


def _note_error(err) -> None:
    global last_error
    last_error = f"{type(err).__name__}: {err}"[:300] if isinstance(err, Exception) else str(err)[:300]
    stats["last_error"] = last_error
    stats["last_error_at"] = time.time()


_rate_lock = asyncio.Lock()
_next_slot = 0.0


async def _throttle() -> None:
    """Global token gate: at most FBA_RATE_LIMIT requests/second across every
    concurrent lookup, by spacing request start times 1/rate apart."""
    global _next_slot
    if FBA_RATE_LIMIT <= 0:
        return
    async with _rate_lock:
        now = time.monotonic()
        wait = _next_slot - now
        _next_slot = max(now, _next_slot) + 1.0 / FBA_RATE_LIMIT
    if wait > 0:
        await asyncio.sleep(wait)


async def _get(client: httpx.AsyncClient, url: str, *, params=None, timeout=None) -> httpx.Response | None:
    """Every FBA request goes through here: rate-limited, counted, optionally
    logged, and a transport failure (TLS, DNS, timeout) is recorded and
    returned as None."""
    await _throttle()
    stats["requests"] += 1
    t0 = time.time()
    shown = url.replace(FBA_BASE_URL, "") + (
        "?" + "&".join(f"{k}={v}" for k, v in params.items()) if params else "")
    try:
        resp = await client.get(url, params=params, headers=_HEADERS, timeout=timeout or FBA_TIMEOUT)
    except Exception as e:
        stats["exceptions"] += 1
        _note_error(e)
        if FBA_DEBUG:
            print(f"    FBA → GET {shown} → {type(e).__name__}: {str(e)[:160]} ({(time.time() - t0) * 1000:.0f}ms)")
        return None
    if 200 <= resp.status_code < 300:
        stats["http_2xx"] += 1
        stats["last_ok_at"] = time.time()
    elif resp.status_code == 404:
        stats["http_404"] += 1
    else:
        stats["http_other"] += 1
        _note_error(f"HTTP {resp.status_code} from {shown}: {resp.text[:120]}")
    if FBA_DEBUG:
        print(f"    FBA → GET {shown} → HTTP {resp.status_code} ({(time.time() - t0) * 1000:.0f}ms)")
    return resp

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
        # ── 1. Direct lookup (fast path, exact name) ──────────────────────
        resp = await _get(client, f"{FBA_BASE_URL}/inventory/{device_name}.conf")
        if resp is None:
            failed = True
        elif resp.status_code == 200:
            try:
                body = resp.json()
                if body.get("success") and body.get("data"):
                    return device_name, body["data"]
            except Exception as e:
                failed = True
                _note_error(e)
        elif resp.status_code != 404:
            failed = True

        # ── 2. Search fallback (handles HA suffixes: -A/-B, -1/-2, -pri/-sec) ──
        # FBA's search is case-insensitive, so one query covers every name case.
        for query in (device_name,):
            try:
                resp = await _get(client, f"{FBA_BASE_URL}/inventory", params={"firewall": query})
                if resp is None:
                    failed = True
                    continue
                if resp.status_code != 200:
                    failed = True
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
                    dr = await _get(client, detail_url)
                    if dr is None or dr.status_code != 200:
                        failed = True
                        continue
                    try:
                        db = dr.json()
                    except Exception as e:
                        failed = True
                        _note_error(e)
                        continue
                    if db.get("success") and db.get("data"):
                        details.append(db["data"])
                        filenames.append(item.get("filename", ""))

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
            resp = await _get(client, config_url, timeout=max(FBA_TIMEOUT, 60))
        if resp is None or resp.status_code != 200:
            return None
        body = resp.json()
        raw = (body.get("data") or {}).get("raw_config") if body.get("success") else None
        return raw if isinstance(raw, str) and raw.strip() else None
    except Exception as e:
        _note_error(e)
        return None
