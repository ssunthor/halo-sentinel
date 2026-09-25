"""
FBA (Firewall Baseline Analysis) API client.
Fetches device configuration analysis from the FBA API and caches results
in SQLite so the API is only hit when data is stale (>24h).

How the FBA external API behaves (fortibleed-analyzer/rest_api/routers/external.py):

  GET /inventory?limit=1000&offset=N   the whole inventory, ordered by filename,
                                       1000 per page; items carry analyzed /
                                       vulnerable / last_analyzed_at but not
                                       findings. ~10k configs → 11 requests.
  GET /inventory?firewall=X            filename ILIKE '%X%' (substring, any case)
  GET /inventory/{filename}            exact filename; full audit incl. findings
  GET /config/{filename}               raw config text

Enrichment therefore does NOT look devices up one by one. Each cycle it pulls
the complete listing (plan_enrichment), matches every Fortinet device locally
(exact filename, else recognised HA-node suffixes), and fetches the detail only
for devices whose last_analyzed_at changed since we last stored it. A device
absent from the complete listing is a trustworthy "not found" at zero cost.

_fetch_one / fetch_configs_chunk remain for the on-demand re-check endpoint:
one search request for a miss, plus one detail per HA node for a hit.

All requests go through one global rate limiter (FBA_RATE_LIMIT requests per
second, default 5) so the enrichment run cannot flood the GIA API.
"""

import asyncio
import os
import re
import time
import httpx

# One GIA API root serves both FBA (/fba) and SAM/DIU (/sam/diu). Production
# reaches GIA under a different name, so override the root with GIA_API_URL;
# FBA_BASE_URL / GIA_DIU_URL remain per-service overrides on top of it.
GIA_API_URL  = os.getenv("GIA_API_URL", "https://gia-ai.gt-t.net/api").rstrip("/")
FBA_BASE_URL = os.getenv("FBA_BASE_URL", f"{GIA_API_URL}/fba").rstrip("/")
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


_HA_SUFFIX = re.compile(r"^[-_](?:a|b|1|2|pri|sec|primary|secondary|master|slave|node[12])$", re.I)


def match_inventory_items(device_name: str, items: list) -> list:
    """Pick the listing items that ARE this device: the exact filename if
    present, else the device's HA nodes. `CPE-X-1.conf` must not swallow
    `CPE-X-1-S1.conf` when both are separate NetBox devices."""
    want = f"{device_name}.conf".lower()
    exact = [i for i in items if (i.get("filename") or "").lower() == want]
    if exact:
        return exact[:1]
    stem = device_name.lower()
    nodes = []
    for i in items:
        fname = (i.get("filename") or "").lower()
        if fname.startswith(stem) and fname.endswith(".conf"):
            if _HA_SUFFIX.match(fname[len(stem):-len(".conf")]):
                nodes.append(i)
    return nodes


_HA_SUFFIXES = ("-a", "-b", "-1", "-2", "-pri", "-sec", "-primary", "-secondary",
                "-master", "-slave", "-node1", "-node2",
                "_a", "_b", "_1", "_2", "_pri", "_sec", "_primary", "_secondary",
                "_master", "_slave", "_node1", "_node2")


async def list_all_inventory(client: httpx.AsyncClient | None = None) -> list | None:
    """Every item in FBA's inventory (≈11 paged requests). None if any page
    could not be fetched — a partial listing must never be treated as complete,
    or absent devices would be recorded as "not found"."""
    async def run(c):
        items, offset, total = [], 0, None
        while total is None or offset < total:
            resp = await _get(c, f"{FBA_BASE_URL}/inventory", params={"limit": 1000, "offset": offset},
                              timeout=max(FBA_TIMEOUT, 60))
            if resp is None or resp.status_code != 200:
                return None
            try:
                data = resp.json()["data"]
            except Exception as e:
                _note_error(e)
                return None
            page = data.get("items") or []
            total = int(data.get("total") or 0)
            items.extend(page)
            if not page:
                break
            offset += len(page)
        return items
    if client is not None:
        return await run(client)
    async with httpx.AsyncClient(verify=FBA_VERIFY_SSL) as c:
        return await run(c)


def index_inventory(items: list) -> dict:
    """{lowercased filename stem: item}."""
    out = {}
    for i in items:
        fname = (i.get("filename") or "")
        if fname.lower().endswith(".conf"):
            out[fname[:-5].lower()] = i
    return out


def match_device(device_name: str, index: dict) -> list:
    """Items that ARE this device (see match_inventory_items), via dict lookups."""
    stem = device_name.lower()
    exact = index.get(stem)
    if exact:
        return [exact]
    return [index[stem + suf] for suf in _HA_SUFFIXES if stem + suf in index]


def plan_enrichment(devices: list, items: list) -> tuple[list, list]:
    """Decide, from the complete listing, what each of our devices needs.

    devices: [{id, resource_name, fba_source_analyzed_at, fba_scanned_at, fba_error}]
    Returns (to_fetch, not_found):
      to_fetch  [(device, [matching items])] — in FBA and its audit is new or
                changed since we stored it (or we hold nothing yet)
      not_found [device]                     — absent from FBA and not already
                recorded as such
    Devices already up to date need no request at all.
    """
    index = index_inventory(items)
    to_fetch, not_found = [], []
    for dev in devices:
        nodes = match_device(dev["resource_name"], index)
        if not nodes:
            if not dev.get("fba_scanned_at") or not dev.get("fba_error"):
                not_found.append(dev)
            continue
        newest = max((n.get("last_analyzed_at") or "") for n in nodes)
        if not dev.get("fba_scanned_at") or (dev.get("fba_source_analyzed_at") or "") != newest:
            to_fetch.append((dev, nodes))
    return to_fetch, not_found


async def fetch_details(client: httpx.AsyncClient, nodes: list) -> dict | None | object:
    """Full audit for one device from its listing item(s). None = FBA answered
    but no detail (deleted between listing and fetch); LOOKUP_FAILED on error."""
    details, filenames = [], []
    for item in nodes:
        resp = await _get(client, item.get("url") or f"{FBA_BASE_URL}/inventory/{item['filename']}")
        if resp is None or resp.status_code >= 500:
            return LOOKUP_FAILED
        if resp.status_code != 200:
            continue
        try:
            body = resp.json()
        except Exception as e:
            _note_error(e)
            return LOOKUP_FAILED
        if body.get("success") and body.get("data"):
            details.append(body["data"])
            filenames.append(item.get("filename", ""))
    if not details:
        return None
    data = details[0] if len(details) == 1 else _merge_results(details, filenames)
    data["source_analyzed_at"] = max((n.get("last_analyzed_at") or "") for n in nodes)
    return data


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
        # One case-insensitive search finds the exact file and any HA nodes;
        # a direct /inventory/{name}.conf GET would only add a 404 per miss.
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

                items = match_inventory_items(device_name, items)
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
