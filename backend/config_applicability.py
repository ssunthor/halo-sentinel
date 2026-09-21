"""Config-aware CVE applicability — service glue (worker + API).

The analysis itself lives in cve_applicability.py (LLM stages + evidence
validation) and config_sections.py (redaction + parsing); this module feeds
them and persists the results.

Config sources, one store (db.device_configs, REDACTED text only):

    fba    Fortinet configs pulled from the FBA API (`config_url` recorded by
           the FBA enrichment worker). FBA is just a config *source* here — the
           CVE verdicts are Sentinel's own analysis of the full config and are
           not limited to what FBA itself checks (admin ACL / passwords).
    push   Any vendor. A Defense Halo instance PUTs the latest version from its
           git config store. A pushed config is never overwritten by FBA's copy.

Worker cycle:  fetch missing/stale FBA configs → for each device whose CVEs
lack a verdict for its current config hash: resolve per-CVE requirements
(cached per CVE+platform, shared estate-wide) → assess → store verdicts.
Verdicts are keyed by (device name, CVE) and stamped with the config hash, so
a changed config or a newly matched CVE re-queues just that work, and results
survive the delete/re-insert that every scan does to the devices table.

Env:

    CFG_APPLICABILITY_ENABLED   "false" to disable the worker (default true)
    CFG_MAX_CVES_PER_DEVICE     highest-scoring N CVEs assessed per device (40)
    CFG_LINE_BUDGET             max config lines shown to the LLM per call (350)
    CFG_CONFIG_MAX_AGE_HOURS    re-check FBA for a newer config after this (24)
    CFG_MAX_CONFIG_BYTES        reject pushed configs larger than this (5 MiB)
    CONFIG_PUSH_TOKEN           bearer token Halo instances present on push;
                                push is DISABLED (503) while this is unset

Endpoints:

    GET  /api/device/{name}/cve-config       config metadata + per-CVE verdicts
    PUT  /api/device/{name}/config           push a config (Bearer CONFIG_PUSH_TOKEN)
    GET  /api/config-applicability/status    worker + coverage stats

main.py calls configure(...) once the LLM client and thread pool exist, includes
`router`, and starts worker() from startup_event.
"""

import asyncio
import hmac
import os
import time
import traceback
from datetime import datetime, timezone

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel

import config_sections as cs
import cve_applicability as ca
import db
import fba_client

ENABLED = os.getenv("CFG_APPLICABILITY_ENABLED", "true").lower() not in ("0", "false", "no")
MAX_CVES_PER_DEVICE = int(os.getenv("CFG_MAX_CVES_PER_DEVICE", "40"))
LINE_BUDGET = int(os.getenv("CFG_LINE_BUDGET", "350"))
CONFIG_MAX_AGE_HOURS = int(os.getenv("CFG_CONFIG_MAX_AGE_HOURS", "24"))
MAX_CONFIG_BYTES = int(os.getenv("CFG_MAX_CONFIG_BYTES", str(5 * 1024 * 1024)))
CONFIG_PUSH_TOKEN = os.getenv("CONFIG_PUSH_TOKEN", "")

_STARTUP_DELAY = 45
_IDLE_DELAY = 120
_BUSY_DELAY = 60
_DEVICE_DELAY = 1.0
_RETRY_BACKOFF = 1800     # a device whose assessment came back incomplete waits this long

router = APIRouter()

_llm = None
_thread_pool = None
_is_busy = lambda: False   # noqa: E731 — replaced by configure()
_retry_after: dict[str, float] = {}

_stats = {
    "enabled": ENABLED,
    "status": "idle",
    "current_device": None,
    "configs_fetched": 0,
    "devices_assessed": 0,
    "cves_assessed": 0,
    "llm_errors": 0,
    "last_activity": None,
    "last_error": None,
}


def configure(*, llm, thread_pool, is_busy):
    """is_busy() → True while a global scan is running (the worker yields)."""
    global _llm, _thread_pool, _is_busy
    _llm, _thread_pool, _is_busy = llm, thread_pool, is_busy


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def store_config(resource_name: str, source: str, raw: str) -> dict:
    """Redact, parse and persist a raw config. Only redacted text is stored."""
    redacted, n_redactions = cs.redact(raw)
    style, sections = cs.parse_sections(redacted)
    digest = cs.content_hash(redacted)
    changed = db.upsert_device_config(
        resource_name, source, redacted, digest, style, n_redactions, _now()
    )
    return {"changed": changed, "content_hash": digest, "style": style,
            "sections": len(sections), "redactions": n_redactions}


# ---------------------------------------------------------------------------
# Worker
# ---------------------------------------------------------------------------

def _platform_key(device: dict) -> str:
    return (device.get("platform_name") or (device.get("os") or "").split(" ")[0] or "unknown").strip()


def _assess_device_sync(device: dict) -> tuple[int, bool]:
    """Blocking (DB + LLM) — runs in the thread pool.
    Returns (cves_given_a_verdict, complete)."""
    name = device["resource_name"]
    cfg = db.get_device_config(name)
    if not cfg:
        return 0, True
    before = db.get_cve_verdicts(name)
    existing = {cid for cid, v in before.items() if not v["stale"]}
    all_cves = db.get_device_cves(device["id"])
    todo = [c for c in all_cves[:MAX_CVES_PER_DEVICE] if c["id"] not in existing]
    overflow = [c for c in all_cves[MAX_CVES_PER_DEVICE:] if c["id"] not in existing]

    platform = _platform_key(device)
    requirements = db.get_cve_requirements([c["id"] for c in todo], platform)
    missing = [c for c in todo if c["id"] not in requirements]
    skipped = []
    for i in range(0, len(missing), ca.REQUIREMENTS_BATCH):
        batch = missing[i:i + ca.REQUIREMENTS_BATCH]
        fresh = ca.cve_requirements(_llm, platform, batch)
        if not fresh:
            _stats["llm_errors"] += 1   # call failed outright — retried next cycle
            continue
        db.save_cve_requirements(platform, fresh, _now())
        requirements.update(fresh)
        # The model answered but left these out: settle them so one awkward CVE
        # can't keep the device in the queue forever.
        skipped += [c for c in batch if c["id"] not in fresh]

    fba = db.get_device_fba_by_name(name) or {}
    rows = [{"cve_id": c["id"], "verdict": "undetermined",
             "rationale": "Could not determine which configuration this CVE depends on."}
            for c in skipped]
    rows += ca.assess_device(
        _llm, device, cfg["content"], todo, requirements,
        fba_findings=fba.get("fba_findings") if fba.get("fba_analyzed") else None,
        line_budget=LINE_BUDGET,
    )
    # Beyond the per-device cap: record that we looked, so the device leaves the queue.
    rows += [{"cve_id": c["id"], "verdict": "not_assessed",
              "rationale": f"Only the {MAX_CVES_PER_DEVICE} highest-scoring CVEs are assessed per device."}
             for c in overflow]
    db.save_cve_verdicts(name, cfg["content_hash"], rows, _now())
    # The prose "AI Analysis" is written from the verdicts; if they changed, queue
    # it for regeneration so the two never contradict each other.
    if (ca.verdict_fingerprint(before, all_cves)
            != ca.verdict_fingerprint(db.get_cve_verdicts(name), all_cves)):
        db.reset_device_llm_analysis(name)
    assessed = len(rows) - len(overflow)
    return assessed, assessed >= len(todo)


async def _fetch_phase(loop) -> int:
    devices = await loop.run_in_executor(
        _thread_pool, db.get_devices_needing_config_fetch, CONFIG_MAX_AGE_HOURS, 50
    )
    fetched = 0
    for dev in devices:
        if _is_busy():
            break
        name = dev["resource_name"]
        raw = await fba_client.fetch_raw_config(dev["fba_config_url"])
        if raw:
            await loop.run_in_executor(_thread_pool, store_config, name, "fba", raw)
            fetched += 1
            _stats["configs_fetched"] += 1
        else:
            # Unavailable right now — don't re-request it every cycle.
            await loop.run_in_executor(_thread_pool, db.touch_device_config, name, _now())
    return fetched


async def _assess_phase(loop) -> int:
    devices = await loop.run_in_executor(_thread_pool, db.get_devices_needing_cve_assessment, 25)
    now = time.time()
    done = 0
    for dev in devices:
        if _is_busy():
            break
        name = dev["resource_name"]
        if _retry_after.get(name, 0) > now:
            continue
        _stats["status"], _stats["current_device"] = "assessing", name
        t0 = time.time()
        assessed, complete = await loop.run_in_executor(_thread_pool, _assess_device_sync, dev)
        print(f"🧩 Config applicability: {name} — {assessed} CVE(s) assessed in {time.time() - t0:.1f}s"
              f"{'' if complete else ' (incomplete, will retry)'}")
        if complete:
            _retry_after.pop(name, None)
        else:
            _retry_after[name] = time.time() + _RETRY_BACKOFF
        _stats["devices_assessed"] += 1
        _stats["cves_assessed"] += assessed
        _stats["last_activity"] = _now()
        done += 1
        await asyncio.sleep(_DEVICE_DELAY)
    _stats["current_device"] = None
    return done


async def worker():
    if not ENABLED:
        print("ℹ️  Config applicability disabled (CFG_APPLICABILITY_ENABLED=false).")
        return
    await asyncio.sleep(_STARTUP_DELAY)
    print("✅ Config applicability worker started.")
    loop = asyncio.get_running_loop()
    while True:
        try:
            if _is_busy():
                _stats["status"] = "paused"
                await asyncio.sleep(_BUSY_DELAY)
                continue
            _stats["status"] = "fetching"
            fetched = await _fetch_phase(loop)
            assessed = await _assess_phase(loop)
            _stats["status"] = "idle"
            if not fetched and not assessed:
                await asyncio.sleep(_IDLE_DELAY)
        except Exception as e:
            _stats["status"] = "error"
            _stats["last_error"] = str(e)
            print(f"❌ Config applicability worker error: {e}")
            traceback.print_exc()
            await asyncio.sleep(_IDLE_DELAY)


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------

class ConfigPush(BaseModel):
    content: str


@router.get("/api/device/{resource_name}/cve-config")
async def get_device_cve_config(resource_name: str):
    """Config metadata + per-CVE applicability verdicts for one device.
    The config text itself is never returned — only the validated evidence
    snippets stored with each verdict."""
    loop = asyncio.get_running_loop()
    cfg = await loop.run_in_executor(_thread_pool, db.get_device_config, resource_name, False)
    verdicts = await loop.run_in_executor(_thread_pool, db.get_cve_verdicts, resource_name)
    verdicts = {k: v for k, v in verdicts.items() if v["verdict"] != "not_assessed"}
    return {"has_config": bool(cfg), "config": cfg, "verdicts": verdicts}


@router.put("/api/device/{resource_name}/config")
async def push_device_config(resource_name: str, body: ConfigPush,
                             authorization: str | None = Header(None)):
    if not CONFIG_PUSH_TOKEN:
        raise HTTPException(503, "Config push is disabled (CONFIG_PUSH_TOKEN is not set).")
    supplied = (authorization or "").removeprefix("Bearer ").strip()
    if not hmac.compare_digest(supplied, CONFIG_PUSH_TOKEN):
        raise HTTPException(401, "Invalid or missing bearer token.")
    if not body.content.strip():
        raise HTTPException(400, "Empty config.")
    if len(body.content.encode("utf-8", "replace")) > MAX_CONFIG_BYTES:
        raise HTTPException(413, f"Config exceeds {MAX_CONFIG_BYTES} bytes.")
    loop = asyncio.get_running_loop()
    result = await loop.run_in_executor(
        _thread_pool, store_config, resource_name, "push", body.content
    )
    _retry_after.pop(resource_name, None)
    return {"resource_name": resource_name, **result}


@router.get("/api/config-applicability/status")
async def get_status():
    loop = asyncio.get_running_loop()
    counts = await loop.run_in_executor(_thread_pool, db.get_config_applicability_counts)
    return {**_stats, "push_enabled": bool(CONFIG_PUSH_TOKEN), **counts}
