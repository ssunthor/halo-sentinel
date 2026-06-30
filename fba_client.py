"""
FBA (Firewall Baseline Analysis) API client.
Fetches device configuration analysis from the FBA API and caches results
in SQLite so the API is only hit when data is stale (>24h).
"""

import asyncio
import os
import httpx

FBA_BASE_URL = os.getenv("FBA_BASE_URL", "https://gia-ai.gt-t.net/api/fba")
FBA_API_KEY  = os.getenv("FBA_API_KEY",  "6PSYFpBW4Ax48V2CNpXuid1679tTtMKk")
FBA_TIMEOUT  = float(os.getenv("FBA_TIMEOUT_SECONDS", "15"))

_HEADERS = {"X-API-Key": FBA_API_KEY}


async def _fetch_one(
    client: httpx.AsyncClient,
    device_name: str,
    semaphore: asyncio.Semaphore,
) -> tuple[str, dict | None]:
    """
    Try resource_name as-is, then lowercase.
    Returns (device_name, result_dict | None).
    result_dict keys: analyzed, vulnerable, vuln_acl, vuln_password,
                      error, reason, findings (list)
    """
    async with semaphore:
        for name in _name_variants(device_name):
            url = f"{FBA_BASE_URL}/inventory/{name}.conf"
            try:
                resp = await client.get(url, headers=_HEADERS, timeout=FBA_TIMEOUT)
                if resp.status_code == 200:
                    body = resp.json()
                    if body.get("success") and body.get("data"):
                        return device_name, body["data"]
                elif resp.status_code == 404:
                    continue  # try next variant
            except Exception:
                continue
        return device_name, None


def _name_variants(name: str) -> list[str]:
    """Return name variants to try in order (exact → lowercase → uppercase)."""
    variants = [name]
    if name != name.lower():
        variants.append(name.lower())
    if name != name.upper():
        variants.append(name.upper())
    return variants


async def fetch_configs_chunk(
    device_names: list[str],
    concurrency: int = 20,
) -> dict[str, dict | None]:
    """
    Fetch FBA config data for a chunk of device names.
    Returns {device_name: data_dict | None} where None means no config found.
    """
    semaphore = asyncio.Semaphore(concurrency)
    results: dict[str, dict | None] = {}

    async with httpx.AsyncClient() as client:
        tasks = [_fetch_one(client, name, semaphore) for name in device_names]
        for coro in asyncio.as_completed(tasks):
            name, data = await coro
            results[name] = data

    return results
