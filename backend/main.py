import asyncio
import json
import time
import threading
import re
import os
import urllib.parse
import math
from collections import deque
from pathlib import Path
from fastapi import FastAPI, Response, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
import httpx
from datetime import datetime, timedelta, timezone
import config_applicability
import cve_applicability
import email_report
import fba_client
import gia_client
from concurrent.futures import ThreadPoolExecutor
from pydantic import BaseModel
import redis
import traceback
import uvloop
from llm_interface import vLLMClient
import db

try:
    import orjson
    def json_dumps(x): return orjson.dumps(x).decode('utf-8')
    def json_loads(x): return orjson.loads(x)
except ImportError:
    class SafeJSONEncoder(json.JSONEncoder):
        def default(self, obj):
            if isinstance(obj, float):
                if math.isnan(obj) or math.isinf(obj):
                    return None
            return super().default(obj)

    def json_dumps(x):
        try:
            return json.dumps(x, allow_nan=False)
        except ValueError:
            s = json.dumps(x, allow_nan=True)
            return s.replace(': NaN', ': null').replace(': Infinity', ': null').replace(': -Infinity', ': null')

    def json_loads(x): return json.loads(x)

def load_cache(file_path):
    if os.path.exists(file_path):
        with open(file_path, "r") as f: return json_loads(f.read())
    return {}

def save_cache(file_path, data):
    with open(file_path, "w") as f: f.write(json_dumps(data))

asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())

# --- CONFIGURATION ---
NETBOX_URL = os.getenv("NETBOX_URL", "http://localhost:8000")
NETBOX_TOKEN = os.getenv("NETBOX_TOKEN", "YOUR_NETBOX_API_TOKEN")

VLLM_ENDPOINT = os.getenv("VLLM_ENDPOINT", "http://10.250.133.8:8080/vllm-gemma3-27b/v1/chat/completions")
VLLM_MODEL = os.getenv("VLLM_MODEL", "google/gemma-3-27b-it")
VLLM_TOKEN = os.getenv("VLLM_TOKEN", "NONE")

LLM_AUTH_URL = os.getenv("LLM_AUTH_URL")
LLM_CLIENT_ID = os.getenv("LLM_CLIENT_ID")
LLM_CLIENT_SECRET = os.getenv("LLM_CLIENT_SECRET")

REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
REDIS_DB = int(os.getenv("REDIS_DB", 0))
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", "password")

DAILY_SCAN_TIME_UTC  = os.getenv("DAILY_SCAN_TIME_UTC",  "02:00")
FBA_ENABLED          = os.getenv("FBA_ENABLED", "true").lower() not in ("0", "false", "no")
FBA_RETRY_HOURS      = int(os.getenv("FBA_RETRY_HOURS", "1"))   # after a FAILED lookup (not a "not found")
FBA_SYNC_MINUTES     = int(os.getenv("FBA_SYNC_MINUTES", "60"))  # how often to re-pull FBA's inventory listing

CACHE_DIR = "/app/cache"
CVE_CACHE_FILE = os.path.join(CACHE_DIR, "cve_cache.json")
LLM_ANALYSIS_CACHE_FILE = os.path.join(CACHE_DIR, "llm_analysis_cache.json")
CACHE_MAX_AGE_HOURS = 24

if not os.path.exists(CACHE_DIR):
    os.makedirs(CACHE_DIR, exist_ok=True)

# --- LLM CLIENT ---
vllm_config = {
    "model": VLLM_MODEL,
    "base_url": VLLM_ENDPOINT.split("/v1")[0] if "/v1" in VLLM_ENDPOINT else VLLM_ENDPOINT,
    "api_endpoint": "/v1/chat/completions",
    "chat_timeout_seconds": 300,
    "num_ctx": 4096,
    "ssl_verify": False,
    "enable_thinking": False
}
vllm_auth_cfg = {
    "auth_url": LLM_AUTH_URL,
    "client_id": LLM_CLIENT_ID,
    "client_secret": LLM_CLIENT_SECRET
} if LLM_AUTH_URL and LLM_CLIENT_ID and LLM_CLIENT_SECRET else None
vllm_client = vLLMClient(vllm_config, vllm_auth_cfg, api_key=VLLM_TOKEN)

# --- REDIS ---
r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB, password=REDIS_PASSWORD, decode_responses=True)

# --- THREAD POOL ---
thread_pool = ThreadPoolExecutor(max_workers=16)

# --- SHARED CACHES (loaded at startup) ---
cve_cache = load_cache(CVE_CACHE_FILE)
llm_analysis_cache = load_cache(LLM_ANALYSIS_CACHE_FILE)

# --- IN-MEMORY SCAN STATE (per tenant) ---
# tenant_id (str) -> asyncio.Queue of device result dicts; None when no scan running
_scan_queues: dict[str, asyncio.Queue] = {}
_scan_state: dict[str, dict] = {}
_scan_tasks: dict[str, asyncio.Task] = {}

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# Config-aware CVE applicability (per-CVE verdicts from device configs)
config_applicability.configure(
    llm=vllm_client,
    thread_pool=thread_pool,
    is_busy=lambda: _global_scan_state.get("status") == "running",
)
app.include_router(config_applicability.router)


# ---------------------------------------------------------------------------
# CACHE HELPERS — thin shims delegating to db module
# ---------------------------------------------------------------------------

def load_tenant_results(tenant_id: str) -> dict:
    return db.load_tenant_results(tenant_id)

def save_tenant_results(tenant_id: str, data: dict):
    db.save_tenant_results(tenant_id, data)

def load_tenant_summary(tenant_id: str) -> dict:
    return db.load_tenant_summary(tenant_id)

def save_tenant_summary(tenant_id: str, data: dict):
    db.save_tenant_summary(tenant_id, data)

def get_cache_age_hours(tenant_id: str) -> float | None:
    return db.get_cache_age_hours(tenant_id)


# ---------------------------------------------------------------------------
# NVD VULNERABILITY BROKER
# ---------------------------------------------------------------------------

class VulnerabilityRequestBroker:
    def __init__(self, cve_cache_ref):
        self.queue = asyncio.Queue()
        self.cve_cache = cve_cache_ref
        self.processed_requests = {}
        self.in_flight = {}

    def _normalize_query(self, query: str) -> str:
        if not query: return ""
        return re.sub(r'\s+', ' ', query.strip())

    async def worker(self, client):
        while True:
            search_query, _ = await self.queue.get()
            if search_query in self.cve_cache:
                print(f"      ⚡ CVE CACHE: Hit for '{search_query}'")
                cves_data = self.cve_cache[search_query]
            else:
                encoded = urllib.parse.quote(search_query)
                url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={encoded}"
                try:
                    print(f"      🌐 NVD API: Requesting '{search_query}'...")
                    resp = await client.get(url, timeout=30)
                    if resp.status_code == 200:
                        cves_data = resp.json()
                        self.cve_cache[search_query] = cves_data
                        print(f"      ✅ NVD API: Found {len(cves_data.get('vulnerabilities', []))} CVEs for '{search_query}'")
                        save_cache(CVE_CACHE_FILE, self.cve_cache)
                    else:
                        print(f"      ❌ NVD API Error {resp.status_code} for '{search_query}'")
                        cves_data = {"vulnerabilities": []}
                except Exception as e:
                    print(f"      ❌ NVD API Exception for '{search_query}': {e}")
                    cves_data = {"vulnerabilities": []}
                await asyncio.sleep(10)

            self.processed_requests[search_query] = cves_data
            if search_query in self.in_flight:
                waiters = self.in_flight.pop(search_query)
                for ev in waiters:
                    ev.set()
            self.queue.task_done()

    async def request_vulnerabilities(self, search_query):
        norm_query = self._normalize_query(search_query)
        if norm_query in self.processed_requests: return self.processed_requests[norm_query]
        if norm_query in self.cve_cache: return self.cve_cache[norm_query]
        if norm_query in self.in_flight:
            event = asyncio.Event()
            self.in_flight[norm_query].append(event)
            await event.wait()
            return self.processed_requests[norm_query]
        event = asyncio.Event()
        self.in_flight[norm_query] = [event]
        await self.queue.put((norm_query, event))
        await event.wait()
        return self.processed_requests[norm_query]


# ---------------------------------------------------------------------------
# LLM HELPERS
# ---------------------------------------------------------------------------

def _analysis_cache_key(resource_name, cves, verdicts=None, fba_data=None):
    """Prose-analysis cache key. Devices with config verdicts and/or an FBA
    audit get fingerprints appended, so an analysis written before that data
    existed (or under different data) is regenerated instead of reused."""
    key = f"{resource_name}-{'-'.join(sorted(c['id'] for c in cves))}"
    fp = cve_applicability.verdict_fingerprint(verdicts, cves)
    if fp:
        key += f"-cfg:{fp}"
    fp = cve_applicability.fba_fingerprint(fba_data)
    if fp:
        key += f"-fba:{fp}"
    return key


async def get_llm_analysis(resource_name, model, os_info, cves, fba_data=None, verdicts=None):
    def call_llm():
        try:
            cve_list = "\n".join([f"- {c['id']}: {c['description']} (Score: {c['score']})" for c in cves])

            fba_section = ""
            if fba_data and fba_data.get("fba_analyzed"):
                vuln_flag  = "VULNERABLE" if fba_data.get("fba_vulnerable") else "NOT VULNERABLE"
                acl_flag   = "EXPOSED"    if fba_data.get("fba_vuln_acl")   else "OK"
                pwd_flag   = "WEAK"       if fba_data.get("fba_vuln_password") else "OK"
                reason     = fba_data.get("fba_reason") or ""
                findings   = fba_data.get("fba_findings") or []
                finding_lines = "\n".join(
                    f"  [{f.get('severity','?')}] {f.get('category','')}: {f.get('issue','')}"
                    for f in findings[:10]
                )
                fba_section = (
                    f"\n\nLIVE CONFIGURATION ANALYSIS (from FBA config audit):\n"
                    f"Overall status: {vuln_flag} | ACL exposure: {acl_flag} | Password security: {pwd_flag}\n"
                    f"Summary: {reason}\n"
                    f"Specific findings:\n{finding_lines}\n\n"
                    f"Cross-reference the above NVD CVEs with the live configuration findings. "
                    f"Identify which CVEs are likely ACTIVELY EXPLOITABLE given the device's current configuration "
                    f"versus those that may be mitigated by the configuration. "
                    f"Highlight any configuration issues that independently increase risk beyond the CVEs."
                )

            prompt = (
                f"Analyze the security risk for resource '{resource_name}' "
                f"(Model: {model}, OS: {os_info}).\n\n"
                f"The following vulnerabilities were found:\n{cve_list}"
                f"{fba_section}"
                f"{cve_applicability.verdicts_prompt_block(verdicts, cves)}\n\n"
                f"Provide a concise assessment of the impact and recommended actions."
            )
            messages = [{"role": "user", "content": prompt}]
            response = vllm_client.get_chat_completion(messages, temperature=0.1, json_mode=False, max_tokens=2048)
            if response and "content" in response:
                return response["content"].strip()
            return "Analysis unavailable."
        except Exception as e:
            return f"Analysis failed: {str(e)}"

    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(thread_pool, call_llm)


async def generate_estate_summary(tenant_id: str, tenant_name: str, devices: list):
    """Generate an LLM estate-level summary after a scan completes."""
    previous = load_tenant_summary(tenant_id)
    vuln = [d for d in devices if d.get("is_vulnerable")]

    if not vuln:
        summary = {
            "risk_posture": "Clean",
            "risk_summary": f"No vulnerable devices found across {len(devices)} scanned resources.",
            "top_cves": [],
            "recommendations": ["Maintain current patch cadence.", "Continue regular scanning."],
            "trend": "stable" if previous else "new_scan",
            "trend_detail": "No vulnerabilities detected." if not previous else "No change — estate remains clean.",
            "generated_at": datetime.utcnow().isoformat(),
            "previous_generated_at": previous.get("generated_at") if previous else None,
        }
        save_tenant_summary(tenant_id, summary)
        return summary

    # Build CVE frequency map across estate
    cve_freq: dict[str, dict] = {}
    for d in vuln:
        for cve in d.get("cves", []):
            cid = cve["id"]
            if cid not in cve_freq:
                cve_freq[cid] = {"id": cid, "score": cve["score"], "severity": cve["severity"], "count": 0}
            cve_freq[cid]["count"] += 1

    top_cves = sorted(cve_freq.values(), key=lambda x: (x["score"], x["count"]), reverse=True)[:10]

    device_summaries = "\n".join([
        f"- {d['resource_name']} ({d['os']}): {len(d['cves'])} CVEs, highest score {d['highest_severity_score']:.1f}"
        for d in sorted(vuln, key=lambda x: x["highest_severity_score"], reverse=True)[:30]
    ])

    prev_section = ""
    if previous and previous.get("generated_at"):
        prev_vuln_count = previous.get("vulnerable_device_count", "unknown")
        prev_max_score = previous.get("max_severity_score", "unknown")
        prev_section = (
            f"\n\nPREVIOUS SCAN (for comparison, conducted {previous['generated_at']}):\n"
            f"- Vulnerable devices: {prev_vuln_count}\n"
            f"- Highest CVE score: {prev_max_score}\n"
            f"Please comment on whether the security posture is improving, declining, or stable compared to the previous scan."
        )

    prompt = (
        f"You are a senior security analyst. Provide a concise estate-level vulnerability assessment for tenant '{tenant_name}'.\n\n"
        f"CURRENT SCAN RESULTS:\n"
        f"- Total devices scanned: {len(devices)}\n"
        f"- Vulnerable devices: {len(vuln)}\n"
        f"- Highest CVE score: {max(d['highest_severity_score'] for d in vuln):.1f}\n\n"
        f"Most critical devices:\n{device_summaries}\n\n"
        f"Top CVEs by frequency/severity:\n"
        + "\n".join([f"- {c['id']} (Score {c['score']}, {c['severity']}, affects {c['count']} device(s))" for c in top_cves[:5]])
        + prev_section
        + "\n\nRespond with a JSON object containing:\n"
        "- risk_posture: one of Critical/High/Medium/Low/Clean\n"
        "- risk_summary: one concise sentence describing the overall estate risk\n"
        "- top_cves: array of top 5 CVE objects {id, score, severity, affected_count, action}\n"
        "- recommendations: array of 3-5 prioritized remediation strings\n"
        "- trend: one of improving/declining/stable/new_scan\n"
        "- trend_detail: one sentence explaining the trend vs previous scan"
    )

    print(f"📝 ESTATE SUMMARY: Generating for tenant {tenant_id} ({tenant_name})...")

    def call_llm():
        messages = [{"role": "user", "content": prompt}]
        return vllm_client.get_chat_completion(messages, temperature=0.1, json_mode=True, max_tokens=4096)

    loop = asyncio.get_running_loop()
    response = await loop.run_in_executor(thread_pool, call_llm)

    if response and "content" in response:
        try:
            parsed = json_loads(response["content"])
        except Exception:
            parsed = {"risk_posture": "Unknown", "risk_summary": response["content"], "top_cves": [], "recommendations": [], "trend": "unknown", "trend_detail": ""}

        summary = {
            **parsed,
            "generated_at": datetime.utcnow().isoformat(),
            "previous_generated_at": previous.get("generated_at") if previous else None,
            "vulnerable_device_count": len(vuln),
            "total_device_count": len(devices),
            "max_severity_score": max(d["highest_severity_score"] for d in vuln),
        }
        save_tenant_summary(tenant_id, summary)
        print(f"  ✅ Estate summary saved for tenant {tenant_id}")
        return summary
    else:
        print(f"  ❌ Estate summary LLM returned no response for tenant {tenant_id}")
        return None


# ---------------------------------------------------------------------------
# DEVICE SCANNING — shared helpers
# ---------------------------------------------------------------------------

def _build_nvd_query(os_name: str, os_version: str) -> str | None:
    """Return the NVD keyword search string for a platform/version combo, or None if insufficient data."""
    if not os_name or not os_version:
        return None
    version_clean = re.sub(r'^v', '', str(os_version))
    if "forti" in os_name.lower():
        m = re.search(r'(\d+\.\d+\.\d+)', version_clean)
        if m:
            version_clean = m.group(1)
    gvm = re.search(r'(\d+\.\d+(?:\.\d+)?(?:[a-zA-Z0-9.\-x]*))', os_name, re.IGNORECASE)
    if gvm and version_clean:
        gv = gvm.group(1)
        npm = re.match(r'(\d+\.\d+)', gv)
        if npm and npm.group(1) in version_clean:
            cleaned = re.sub(r'\s+', ' ', re.sub(r'\s*\b' + re.escape(gv) + r'\b', '', os_name, flags=re.IGNORECASE)).strip()
            return f"{cleaned} {version_clean}"
        return f"{os_name} {version_clean}"
    return f"{os_name} {version_clean}" if version_clean else os_name


def _version_key(v: str) -> tuple:
    """Semantic version tuple for comparison. '17.9.4' → (17, 9, 4)."""
    parts = []
    for seg in re.split(r'[.\-_]', v or ''):
        m = re.match(r'^(\d+)', seg)
        if m:
            parts.append(int(m.group(1)))
    return tuple(parts) if parts else (0,)


def _extract_recommended_version(cves_data: dict) -> str | None:
    """
    Scan NVD CPE configuration data across all CVEs and return the highest
    versionEndExcluding (or versionEndIncluding as fallback), which represents
    the minimum version that closes all known vulnerabilities.
    Returns None if no structured version range data is present.
    """
    candidates = []
    for item in cves_data.get("vulnerabilities", []):
        for config in item.get("cve", {}).get("configurations", []):
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    if not match.get("vulnerable"):
                        continue
                    v = match.get("versionEndExcluding") or match.get("versionEndIncluding")
                    if v and v.strip():
                        candidates.append(v.strip())
    if not candidates:
        return None
    return max(candidates, key=_version_key)


def _parse_cve_response(cves_data: dict) -> tuple[list, float]:
    """Parse an NVD CVE response into (cve_list, highest_score)."""
    device_cves, highest = [], 0.0
    for item in cves_data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        metrics = cve.get("metrics", {})
        metric, cvss = None, {}
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(key):
                metric = metrics[key][0]
                cvss = metric.get("cvssData", {})
                break
        if not cvss:
            continue
        score = cvss.get("baseScore", 0)
        if score > highest:
            highest = score
        descs = cve.get("descriptions", [])
        desc = next((d["value"] for d in descs if d.get("lang") == "en"), None) or (descs[0].get("value") if descs else "No description available.")
        device_cves.append({
            "id": cve.get("id"),
            "description": desc or "No description available.",
            "score": score,
            "severity": cvss.get("baseSeverity") or (metric.get("baseSeverity") if metric else "UNKNOWN"),
        })
    return device_cves, highest


async def process_netbox_resource(resource, resource_type, client, broker, update_callback=None):
    resource_name = resource.get("name") or f"Resource-{resource.get('id')}"

    if resource_type == "device":
        model = (resource.get("device_type") or {}).get("model") or "Unknown Model"
        platform_info = resource.get("platform")
        os_name = platform_info.get("name") if platform_info else None
        os_version = resource.get("custom_fields", {}).get("os_build")
        serial = resource.get("serial") or ""
        pon = resource.get("custom_fields", {}).get("cmd_pon") or ""
    elif resource_type == "vm":
        model = (resource.get("cluster") or {}).get("name") or "Unknown Cluster"
        platform_info = resource.get("platform")
        os_name = platform_info.get("name") if platform_info else None
        os_version = resource.get("custom_fields", {}).get("os_version")
        serial = ""
        pon = resource.get("custom_fields", {}).get("cmd_pon") or ""
    else:
        return {
            "resource_name": resource_name, "os": "Unknown", "resource_type": "Unknown",
            "resource_category": resource_type, "platform_name": None, "os_version": None,
            "serial": None, "pon": None, "highest_severity_score": 0.0,
            "cves": [], "is_vulnerable": False, "llm_analysis": "Invalid resource type."
        }

    if not os_name or not os_version:
        print(f"      ⏭️ Skipping {resource_name}: Missing Platform ({os_name}) or OS Version ({os_version})")
        return {
            "resource_name": resource_name, "os": f"{os_name or 'Unknown'} {os_version or ''}",
            "resource_type": model, "resource_category": resource_type,
            "platform_name": os_name, "os_version": os_version, "serial": serial, "pon": pon,
            "highest_severity_score": 0.0, "cves": [], "is_vulnerable": False,
            "llm_analysis": "Status Unknown: Missing required NetBox fields (Platform or OS Version)."
        }

    print(f"      🔎 Scanning {resource_name}...")

    initial_search_query = _build_nvd_query(os_name, os_version) or os_name

    final_cves_data = {"vulnerabilities": []}
    current_search_query = initial_search_query

    try:
        cves_data_result = await broker.request_vulnerabilities(current_search_query)
        raw_vulnerabilities_result = cves_data_result.get("vulnerabilities", [])

        if raw_vulnerabilities_result:
            final_cves_data = cves_data_result
        else:
            print(f"      ⚠️ No CVEs for '{current_search_query}'. Attempting simplified search...")
            simplified_version_match = re.match(r'(\d+\.\d+)', str(os_version))
            if simplified_version_match:
                simplified_version = simplified_version_match.group(1)
                temp_os_name = os_name
                gvm = re.search(r'(\d+\.\d+(?:\.\d+)?(?:[a-zA-Z0-9\.\-x]*))', os_name, re.IGNORECASE)
                if gvm:
                    gv = gvm.group(1)
                    if simplified_version in gv:
                        pattern = r'\s*\b' + re.escape(gv) + r'\b'
                        temp_os_name = re.sub(r'\s+', ' ', re.sub(pattern, '', os_name, flags=re.IGNORECASE)).strip()
                simplified_query = f"{temp_os_name} {simplified_version}".strip()
                if simplified_query != current_search_query:
                    print(f"      🌐 Simplified search: '{simplified_query}'...")
                    final_cves_data = await broker.request_vulnerabilities(simplified_query)
                    current_search_query = simplified_query
                else:
                    final_cves_data = cves_data_result
            else:
                final_cves_data = cves_data_result
    except Exception as e:
        print(f"      ❌ NVD search error for '{current_search_query}': {e}")

    print(f"      📊 {resource_name}: {len(final_cves_data.get('vulnerabilities', []))} raw CVEs for '{current_search_query}'")

    # GIA engineering version lookup (cached per platform — one API call shared
    # across all devices on the same platform within the same scan cycle).
    gia_data = None
    try:
        gia_data = await gia_client.lookup_platform_version(os_name)
    except Exception as gia_err:
        print(f"      ⚠️ GIA lookup failed for '{os_name}': {gia_err}")

    try:
        device_cves, highest = _parse_cve_response(final_cves_data)
        recommended_version = _extract_recommended_version(final_cves_data)

        partial_res = {
            "resource_name": resource_name,
            "os": f"{os_name} {os_version or ''}",
            "resource_type": model,
            "resource_category": resource_type,
            "platform_name": os_name,
            "os_version": os_version,
            "recommended_version": recommended_version,
            "gia_recommended_version": (gia_data or {}).get("gia_recommended_version"),
            "serial": serial,
            "pon": pon,
            "highest_severity_score": highest,
            "cves": device_cves,
            "is_vulnerable": len(device_cves) > 0,
            "llm_analysis": "Analyzing vulnerabilities..." if device_cves else "No vulnerabilities detected."
        }
        if update_callback:
            await update_callback(partial_res)

        llm_analysis = partial_res["llm_analysis"]
        if device_cves:
            loop = asyncio.get_running_loop()
            verdicts = await loop.run_in_executor(thread_pool, db.get_cve_verdicts, resource_name)
            fba_data = await loop.run_in_executor(thread_pool, db.get_device_fba_by_name, resource_name)
            key = _analysis_cache_key(resource_name, device_cves, verdicts, fba_data)
            if key in llm_analysis_cache:
                llm_analysis = llm_analysis_cache[key]
            else:
                llm_analysis = await get_llm_analysis(
                    resource_name, model, f"{os_name} {os_version or ''}", device_cves,
                    fba_data=fba_data, verdicts=verdicts,
                )
                llm_analysis_cache[key] = llm_analysis
                save_cache(LLM_ANALYSIS_CACHE_FILE, llm_analysis_cache)

        final_res = {**partial_res, "llm_analysis": llm_analysis}
        if update_callback:
            await update_callback(final_res)

        return final_res

    except Exception as e:
        print(f"      ❌ Error processing {resource_name}: {e}")
        err_res = {
            "resource_name": resource_name,
            "os": f"{os_name or 'Unknown'} {os_version or ''}",
            "is_vulnerable": False,
            "resource_type": model,
            "resource_category": resource_type,
            "platform_name": os_name,
            "os_version": os_version,
            "recommended_version": None,
            "gia_recommended_version": (gia_data or {}).get("gia_recommended_version"),
            "serial": serial,
            "pon": pon,
            "highest_severity_score": 0.0,
            "cves": [],
            "llm_analysis": f"Error: {str(e)}"
        }
        if update_callback:
            await update_callback(err_res)
        return err_res


def _netbox_next(next_url: str | None) -> str | None:
    """Rewrite the host/scheme of a NetBox pagination 'next' URL to match NETBOX_URL.

    NetBox constructs 'next' from its own configured base URL, which may differ
    from the internal URL used inside Kubernetes. Keeping only the path+query
    from NetBox's response and prepending our configured NETBOX_URL ensures
    pagination works across all network environments.
    """
    if not next_url:
        return None
    parsed = urllib.parse.urlparse(next_url)
    base   = urllib.parse.urlparse(NETBOX_URL)
    return urllib.parse.urlunparse(parsed._replace(scheme=base.scheme, netloc=base.netloc))


async def run_tenant_scan(tenant_id: str, tenant_name: str):
    """Full scan for both devices and VMs for the given tenant. Updates _scan_state and pushes to _scan_queues."""
    global cve_cache, llm_analysis_cache

    state = _scan_state.setdefault(tenant_id, {})
    state["status"] = "running"
    state["scanned"] = 0
    state["total"] = 0
    state["started_at"] = datetime.utcnow().isoformat()

    # Persist running status to Redis so the /status endpoint works across requests
    r.hset(f"scan:{tenant_id}", mapping={"status": "running", "scanned": 0, "total": 0, "started_at": state["started_at"]})

    queue = _scan_queues.setdefault(tenant_id, asyncio.Queue())
    results_map: dict[str, dict] = {}

    headers = {"Authorization": f"Token {NETBOX_TOKEN}", "Content-Type": "application/json", "Accept": "application/json"}
    broker = VulnerabilityRequestBroker(cve_cache)

    async with httpx.AsyncClient(verify=False) as client:
        broker_task = asyncio.create_task(broker.worker(client))

        try:
            all_devices = []
            for resource_type in ("device", "vm"):
                url = (
                    f"{NETBOX_URL}/api/virtualization/virtual-machines/?tenant_id={tenant_id}&status=active&limit=0"
                    if resource_type == "vm"
                    else f"{NETBOX_URL}/api/dcim/devices/?tenant_id={tenant_id}&status=active&limit=0"
                )
                page = 1
                while url:
                    print(f"  📡 [{tenant_name}] Fetching {resource_type} page {page}...")
                    try:
                        resp = await client.get(url, headers=headers, timeout=60)
                        if resp.status_code == 200:
                            data = resp.json()
                            results = data.get("results", [])
                            for d in results:
                                d["_resource_type"] = resource_type
                            all_devices.extend(results)
                            print(f"    ✅ Page {page}: {len(results)} {resource_type}s (total {len(all_devices)})")
                            url = _netbox_next(data.get("next"))
                            page += 1
                        else:
                            print(f"    ❌ Error fetching {resource_type}s: {resp.status_code}")
                            break
                    except Exception as e:
                        print(f"    ❌ HTTP error page {page}: {e}")
                        break

            state["total"] = len(all_devices)
            r.hset(f"scan:{tenant_id}", "total", len(all_devices))
            print(f"📦 [{tenant_name}] Total resources: {len(all_devices)}")

            # Seed results_map with skeleton entries and push them to SSE queue immediately
            for d in all_devices:
                rtype = d.get("_resource_type", "device")
                rname = d.get("name") or f"Resource-{d.get('id')}"
                if rtype == "vm":
                    model = (d.get("cluster") or {}).get("name") or "Unknown Cluster"
                    platform_info = d.get("platform")
                    os_name = platform_info.get("name") if platform_info else None
                    os_version = d.get("custom_fields", {}).get("os_version")
                    serial = ""
                    pon = d.get("custom_fields", {}).get("cmd_pon") or ""
                else:
                    model = (d.get("device_type") or {}).get("model") or "Unknown Model"
                    platform_info = d.get("platform")
                    os_name = platform_info.get("name") if platform_info else None
                    os_version = d.get("custom_fields", {}).get("os_build")
                    serial = d.get("serial") or ""
                    pon = d.get("custom_fields", {}).get("cmd_pon") or ""

                skeleton = {
                    "resource_name": rname,
                    "os": f"{os_name or 'Unknown'} {os_version or ''}",
                    "resource_type": model,
                    "resource_category": rtype,
                    "platform_name": os_name,
                    "os_version": os_version,
                    "serial": serial,
                    "pon": pon,
                    "highest_severity_score": 0.0,
                    "cves": [],
                    "is_vulnerable": False,
                    "llm_analysis": "Scanning..."
                }
                results_map[rname] = skeleton
                await queue.put({"type": "device", "data": skeleton})

            sem = asyncio.Semaphore(20)

            async def update_cache(res):
                rname = res["resource_name"]
                results_map[rname] = res
                state["scanned"] = sum(1 for v in results_map.values() if v.get("llm_analysis") != "Scanning...")
                r.hset(f"scan:{tenant_id}", "scanned", state["scanned"])
                await queue.put({"type": "device", "data": res})

            async def sem_process(d):
                async with sem:
                    rtype = d.pop("_resource_type", "device")
                    return await process_netbox_resource(d, rtype, client, broker, update_callback=update_cache)

            tasks = [sem_process(d) for d in all_devices]
            if tasks:
                print(f"  📡 [{tenant_name}] Processing {len(tasks)} resources (concurrency 20)...")
                await asyncio.gather(*tasks)

        except Exception as e:
            print(f"  ❌ Critical error in scan for tenant {tenant_id}: {e}")
            traceback.print_exc()

        await broker.queue.join()
        broker_task.cancel()

    # Persist final results
    devices_list = sorted(results_map.values(), key=lambda x: x.get("highest_severity_score", 0), reverse=True)
    save_tenant_results(tenant_id, {
        "tenant_id": tenant_id,
        "tenant_name": tenant_name,
        "scanned_at": datetime.utcnow().isoformat(),
        "devices": devices_list
    })

    state["status"] = "complete"
    r.hset(f"scan:{tenant_id}", mapping={"status": "complete", "scanned": len(devices_list), "total": len(devices_list)})
    print(f"✅ [{tenant_name}] Scan complete. {len(devices_list)} devices.")

    # Generate estate summary
    await generate_estate_summary(tenant_id, tenant_name, devices_list)

    # Signal SSE streams that we're done
    await queue.put({"type": "complete"})
    _scan_tasks.pop(tenant_id, None)


# ---------------------------------------------------------------------------
# GLOBAL SCAN (all tenants, deduplicated NVD queries)
# ---------------------------------------------------------------------------

_global_scan_state: dict = {
    "status": "idle",           # idle | running | complete | error
    "phase": "",
    # inventory
    "devices_fetched": 0,
    "total_devices": 0,
    "physical_devices": 0,
    "virtual_machines": 0,
    "no_platform_count": 0,     # devices skipped (missing platform/version)
    # dedup
    "unique_platforms": 0,      # distinct OS/platform names
    "unique_combos": 0,         # distinct platform+version pairs
    # NVD
    "nvd_queried": 0,
    "nvd_cached": 0,
    "nvd_total": 0,
    "devices_with_cves": 0,     # after fan-out
    # save
    "tenants_saved": 0,
    "total_tenants": 0,
    # timing
    "started_at": None,
    "completed_at": None,
    "elapsed_seconds": None,
    "phase_timings": {},
    "error": None,
}
_global_scan_task: asyncio.Task | None = None
_global_sse_subscribers: list[asyncio.Queue] = []


# ---------------------------------------------------------------------------
# AI WORKER STATS — updated in-place by llm_analysis_worker
# ---------------------------------------------------------------------------
_ai_stats: dict = {
    "status":           "starting",   # starting | idle | analyzing | error
    "current_tenant":   None,
    "current_device":   None,
    "pending_tenants":  0,
    "pending_devices":  0,
    "total_analyzed":   0,            # devices with real analysis written since startup
    "total_api_calls":  0,            # actual vLLM API calls (no cache)
    "total_cache_hits": 0,
    "total_errors":     0,
    "avg_latency_ms":   None,         # rolling avg over last 100 real calls
    "min_latency_ms":   None,         # session min
    "max_latency_ms":   None,         # session max
    "p95_latency_ms":   None,         # 95th-percentile over last 100 calls
    "started_at":       None,
    "last_activity":    None,
    "analyzed_last_24h": 0,           # recomputed each iteration
}
# ring buffers — not serialised to the endpoint directly
_ai_latency_window: deque = deque(maxlen=100)   # ms values for rolling stats
_ai_completion_ts:  deque = deque()              # ISO timestamps; pruned to 24 h


def _update_ai_latency(ms: float):
    global _ai_stats
    _ai_latency_window.append(ms)
    win = list(_ai_latency_window)
    win_sorted = sorted(win)
    _ai_stats["avg_latency_ms"]  = round(sum(win) / len(win))
    _ai_stats["min_latency_ms"]  = round(min(win_sorted))
    _ai_stats["max_latency_ms"]  = round(max(win_sorted))
    p95_idx = max(0, int(len(win_sorted) * 0.95) - 1)
    _ai_stats["p95_latency_ms"]  = round(win_sorted[p95_idx])


def _prune_completion_ts():
    """Remove completion timestamps older than 24 h and update analyzed_last_24h."""
    cutoff = time.time() - 86400
    while _ai_completion_ts and _ai_completion_ts[0] < cutoff:
        _ai_completion_ts.popleft()
    _ai_stats["analyzed_last_24h"] = len(_ai_completion_ts)


async def _push_global(msg: dict):
    dead = []
    for q in _global_sse_subscribers:
        try:
            q.put_nowait(msg)
        except asyncio.QueueFull:
            dead.append(q)
    for q in dead:
        _global_sse_subscribers.remove(q)


async def run_global_scan():
    """
    Fetch all devices/VMs across every tenant, build a unique platform→query map,
    query NVD once per combo, fan results out to devices, and save per-tenant JSON.
    LLM per-device analysis is skipped in bulk mode (100k+ calls would be impractical).
    """
    global cve_cache, _global_scan_task
    state = _global_scan_state
    state.update({
        "status": "running", "phase": "Fetching device inventory",
        "devices_fetched": 0, "total_devices": 0, "physical_devices": 0,
        "virtual_machines": 0, "no_platform_count": 0,
        "unique_platforms": 0, "unique_combos": 0,
        "nvd_queried": 0, "nvd_cached": 0, "nvd_total": 0, "devices_with_cves": 0,
        "tenants_saved": 0, "total_tenants": 0,
        "started_at": datetime.utcnow().isoformat(), "completed_at": None,
        "elapsed_seconds": None, "phase_timings": {}, "error": None,
    })

    t_start = time.time()
    phase_t = t_start
    headers = {"Authorization": f"Token {NETBOX_TOKEN}", "Accept": "application/json"}

    try:
        async with httpx.AsyncClient(verify=False, follow_redirects=True) as client:

            # ----------------------------------------------------------------
            # Phase 1 — inventory all devices + VMs that have a tenant
            # ----------------------------------------------------------------
            all_devices: list[dict] = []
            for rtype, base_url in [
                ("device",  f"{NETBOX_URL}/api/dcim/devices/?limit=1000"),
                ("vm",      f"{NETBOX_URL}/api/virtualization/virtual-machines/?limit=1000"),
            ]:
                state["phase"] = f"Fetching {'physical devices' if rtype == 'device' else 'virtual machines'} from NetBox"
                url = base_url
                page = 1
                while url:
                    try:
                        resp = await client.get(url, headers=headers, timeout=60)
                        resp.raise_for_status()
                        data = resp.json()
                        for d in data.get("results", []):
                            d["_rtype"] = rtype
                        batch = data.get("results", [])
                        all_devices.extend(batch)
                        state["devices_fetched"] = len(all_devices)
                        state["physical_devices"] = sum(1 for d in all_devices if d.get("_rtype") == "device")
                        state["virtual_machines"] = sum(1 for d in all_devices if d.get("_rtype") == "vm")
                        await _push_global({"type": "progress", "state": dict(state)})
                        url = _netbox_next(data.get("next"))
                        page += 1
                    except Exception as e:
                        print(f"  ❌ Global scan page {page} ({rtype}): {e}")
                        break

            state["total_devices"] = len(all_devices)
            state["phase_timings"]["inventory_seconds"] = round(time.time() - phase_t, 1)
            phase_t = time.time()
            print(f"🌍 Global scan: {len(all_devices)} devices fetched in {state['phase_timings']['inventory_seconds']}s")

            # ----------------------------------------------------------------
            # Phase 2 — build unique (query_string → device list) map
            # ----------------------------------------------------------------
            state["phase"] = "Building platform inventory"
            await _push_global({"type": "progress", "state": dict(state)})

            # combo_map: nvd_query → list of raw netbox device dicts
            combo_map: dict[str, list] = {}
            no_platform: list[dict] = []
            platform_names: set[str] = set()

            for d in all_devices:
                rtype = d.get("_rtype", "device")
                pinfo = d.get("platform")
                os_name = pinfo.get("name") if pinfo else None
                if rtype == "vm":
                    os_version = d.get("custom_fields", {}).get("os_version")
                else:
                    os_version = d.get("custom_fields", {}).get("os_build")

                query = _build_nvd_query(os_name, os_version)
                if query:
                    combo_map.setdefault(query, []).append(d)
                    if os_name:
                        platform_names.add(os_name)
                else:
                    no_platform.append(d)

            state["unique_combos"] = len(combo_map)
            state["unique_platforms"] = len(platform_names)
            state["no_platform_count"] = len(no_platform)
            state["phase_timings"]["grouping_seconds"] = round(time.time() - phase_t, 1)
            phase_t = time.time()
            print(f"🔑 Global scan: {len(combo_map)} unique combos across {len(platform_names)} platforms, {len(no_platform)} without platform data")

            # ----------------------------------------------------------------
            # Phase 3 — deduplicated NVD queries via broker
            # ----------------------------------------------------------------
            state["phase"] = f"Querying NVD ({len(combo_map)} unique combos, {len(platform_names)} platforms)"
            state["nvd_total"] = len(combo_map)
            await _push_global({"type": "progress", "state": dict(state)})

            broker = VulnerabilityRequestBroker(cve_cache)
            broker_task = asyncio.create_task(broker.worker(client))
            nvd_results: dict[str, dict] = {}

            async def fetch_one(query: str):
                already_cached = query in cve_cache
                result = await broker.request_vulnerabilities(query)
                nvd_results[query] = result
                state["nvd_queried"] += 1
                if already_cached:
                    state["nvd_cached"] += 1
                await _push_global({"type": "progress", "state": dict(state)})

            # Fan out all queries concurrently — broker serialises the actual API calls
            await asyncio.gather(*[fetch_one(q) for q in combo_map])
            await broker.queue.join()
            broker_task.cancel()

            state["phase_timings"]["nvd_seconds"] = round(time.time() - phase_t, 1)
            phase_t = time.time()
            print(f"📡 Global scan: NVD done in {state['phase_timings']['nvd_seconds']}s ({state['nvd_cached']} cache hits)")

            # ----------------------------------------------------------------
            # Phase 4 — fan out CVE results → group by tenant → save
            # ----------------------------------------------------------------
            state["phase"] = "Saving results per tenant"
            await _push_global({"type": "progress", "state": dict(state)})

            tenant_devices: dict[str, list] = {}
            tenant_names: dict[str, str] = {}
            scan_ts = datetime.utcnow().isoformat()

            # ----------------------------------------------------------------
            # Phase 3b — GIA engineering version lookup (one per platform)
            # ----------------------------------------------------------------
            state["phase"] = f"Looking up engineering versions via GIA ({len(platform_names)} platforms)"
            await _push_global({"type": "progress", "state": dict(state)})

            gia_version_map: dict[str, str | None] = {}
            print(f"  [GIA] starting lookups for {len(platform_names)} platform(s): {sorted(platform_names)[:5]}", flush=True)
            if platform_names:
                gia_tasks = {p: gia_client.lookup_platform_version(p) for p in platform_names}
                gia_results = await asyncio.gather(*gia_tasks.values(), return_exceptions=True)
                for pname, result in zip(gia_tasks.keys(), gia_results):
                    if isinstance(result, Exception):
                        print(f"  [GIA] lookup error for {pname!r}: {result}", flush=True)
                        gia_version_map[pname] = None
                    else:
                        gia_version_map[pname] = (result or {}).get("gia_recommended_version")
                found = sum(1 for v in gia_version_map.values() if v)
                # Print a consolidated summary block — easy to find even if earlier per-lookup
                # lines have scrolled out of the buffer.
                hits   = sorted(p for p, v in gia_version_map.items() if v)
                misses = sorted(p for p, v in gia_version_map.items() if not v)
                print(
                    f"\n{'='*60}\n"
                    f"  [GIA] SCAN COMPLETE — {found}/{len(platform_names)} platforms matched\n"
                    f"  Check /api/gia/status for full cache contents\n"
                    f"  MATCHED ({len(hits)}): {', '.join(hits) or 'none'}\n"
                    f"  NO MATCH ({len(misses)}): {', '.join(misses[:20])}"
                    f"{'...' if len(misses) > 20 else ''}\n"
                    f"{'='*60}\n",
                    flush=True,
                )

            state["phase_timings"]["gia_seconds"] = round(time.time() - phase_t, 1)
            phase_t = time.time()

            def _make_record(d: dict, device_cves: list, highest: float,
                             recommended_version: str | None = None) -> dict:
                rtype = d.get("_rtype", "device")
                pinfo = d.get("platform")
                os_name = pinfo.get("name") if pinfo else None
                if rtype == "vm":
                    model = (d.get("cluster") or {}).get("name") or "Unknown Cluster"
                    os_version = d.get("custom_fields", {}).get("os_version")
                    serial = None
                else:
                    model = (d.get("device_type") or {}).get("model") or "Unknown Model"
                    os_version = d.get("custom_fields", {}).get("os_build")
                    serial = d.get("serial") or None
                pon = d.get("custom_fields", {}).get("cmd_pon") or None
                llm = ("Vulnerabilities found — open this tenant for AI analysis."
                       if device_cves else "No vulnerabilities detected.")
                return {
                    "resource_name": d.get("name") or f"Resource-{d.get('id')}",
                    "os": f"{os_name or 'Unknown'} {os_version or ''}".strip(),
                    "resource_type": model,
                    "resource_category": rtype,
                    "platform_name": os_name,
                    "os_version": os_version,
                    "recommended_version": recommended_version,
                    "gia_recommended_version": gia_version_map.get(os_name) if os_name else None,
                    "serial": serial,
                    "pon": pon,
                    "highest_severity_score": highest,
                    "cves": device_cves,
                    "is_vulnerable": len(device_cves) > 0,
                    "llm_analysis": llm,
                }

            for query, devs in combo_map.items():
                cves_data = nvd_results.get(query, {"vulnerabilities": []})
                device_cves, highest = _parse_cve_response(cves_data)
                recommended_version = _extract_recommended_version(cves_data)
                for d in devs:
                    tenant = d.get("tenant") or {}
                    tid = str(tenant.get("id", ""))
                    tname = tenant.get("name", "Unknown")
                    if not tid:
                        continue
                    tenant_names[tid] = tname
                    tenant_devices.setdefault(tid, []).append(
                        _make_record(d, device_cves, highest, recommended_version)
                    )
                    if device_cves:
                        state["devices_with_cves"] += 1

            state["total_tenants"] = len(tenant_devices)

            for d in no_platform:
                tenant = d.get("tenant") or {}
                tid = str(tenant.get("id", ""))
                tname = tenant.get("name", "Unknown")
                if not tid:
                    continue
                tenant_names[tid] = tname
                tenant_devices.setdefault(tid, []).append(_make_record(d, [], 0.0))

            state["phase"] = f"Saving results for {len(tenant_devices)} tenants"
            await _push_global({"type": "progress", "state": dict(state)})

            for tid, devs in tenant_devices.items():
                devs.sort(key=lambda x: x["highest_severity_score"], reverse=True)
                save_tenant_results(tid, {
                    "tenant_id": tid,
                    "tenant_name": tenant_names[tid],
                    "scanned_at": scan_ts,
                    "devices": devs,
                    "bulk_scan": True,
                })
                state["tenants_saved"] += 1
                if state["tenants_saved"] % 10 == 0:
                    await _push_global({"type": "progress", "state": dict(state)})

            state["phase_timings"]["save_seconds"] = round(time.time() - phase_t, 1)

        elapsed = round(time.time() - t_start, 1)
        state.update({
            "status": "complete",
            "phase": "Complete",
            "elapsed_seconds": elapsed,
            "completed_at": datetime.utcnow().isoformat(),
        })
        print(f"✅ Global scan complete in {elapsed}s — {state['tenants_saved']} tenants, {state['total_devices']} devices, {state['unique_combos']} unique combos")

        # Record a snapshot for trend tracking
        try:
            estate = db.get_estate_stats()
            high_devs = db._connect().execute("""
                SELECT COUNT(DISTINCT d.id) FROM devices d
                JOIN cves c ON d.id = c.device_id WHERE c.score >= 7.0 AND c.score < 9.0
            """).fetchone()[0] or 0
            db.record_scan_snapshot({
                "scan_type":         "global",
                "scanned_at":        state["completed_at"],
                "duration_seconds":  elapsed,
                "total_tenants":     estate.get("total_tenants", 0),
                "total_devices":     state.get("total_devices", 0),
                "physical_devices":  state.get("physical_devices", 0),
                "virtual_machines":  state.get("virtual_machines", 0),
                "vulnerable_devices": estate.get("vulnerable_devices", 0),
                "critical_devices":  estate.get("critical_devices", 0),
                "high_devices":      high_devs,
                "total_cves":        estate.get("total_cve_instances", 0),
                "peak_score":        estate.get("max_score", 0.0),
                "nvd_queried":       state.get("nvd_queried", 0),
                "nvd_cached":        state.get("nvd_cached", 0),
                "nvd_total":         state.get("nvd_total", 0),
            })
        except Exception as snap_err:
            print(f"⚠️  Scan snapshot recording failed: {snap_err}")

    except Exception as e:
        elapsed = round(time.time() - t_start, 1)
        state.update({"status": "error", "error": str(e), "elapsed_seconds": elapsed})
        print(f"❌ Global scan failed after {elapsed}s: {e}")
        traceback.print_exc()

    await _push_global({"type": "complete", "state": dict(state)})
    _global_scan_task = None


# ---------------------------------------------------------------------------
# LLM BACK-FILL WORKER
# ---------------------------------------------------------------------------

# Delays (seconds) — tuned to keep vLLM load gentle
_LLM_WORKER_DEVICE_DELAY  = 3.0    # between individual device calls (non-cache)
_LLM_WORKER_TENANT_DELAY  = 8.0    # between tenants
_LLM_WORKER_IDLE_DELAY    = 120.0  # when no pending work
_LLM_WORKER_ERROR_DELAY   = 30.0   # after an unexpected error

# Max concurrent in-flight LLM calls from this worker
_llm_worker_sem: asyncio.Semaphore | None = None


async def llm_analysis_worker():
    """
    Background worker that back-fills LLM analysis for tenants produced by
    the global bulk scan (which skips per-device and estate-level LLM calls
    because running 100k+ calls serially would be impractical at scan time).

    For each tenant that needs work it:
      1. Runs get_llm_analysis() for every vulnerable device whose analysis
         is still a placeholder string, honouring llm_analysis_cache to avoid
         duplicate API hits.
      2. Calls generate_estate_summary() once device analysis is complete
         (or if only the summary is missing).

    Rate-limited via:
      - _llm_worker_sem  — caps concurrent LLM calls from this worker
      - _LLM_WORKER_DEVICE_DELAY  — sleep after each real (non-cache) API call
      - _LLM_WORKER_TENANT_DELAY  — sleep between tenants
      - _LLM_WORKER_IDLE_DELAY    — sleep when nothing needs doing
    """
    global _llm_worker_sem
    _llm_worker_sem = asyncio.Semaphore(2)

    _ai_stats["started_at"] = datetime.utcnow().isoformat()

    # Let startup tasks (Kafka, Redis, DB) settle before we start hammering the LLM
    await asyncio.sleep(20)
    print("🤖 LLM back-fill worker started")

    loop = asyncio.get_running_loop()

    while True:
        try:
            _prune_completion_ts()

            pending = await loop.run_in_executor(
                thread_pool, db.get_tenants_needing_analysis, 20
            )

            # Update queue depth stats
            _ai_stats["pending_tenants"] = len(pending)
            _ai_stats["pending_devices"] = sum(t.get("pending_devices", 0) for t in pending)

            if not pending:
                _ai_stats["status"] = "idle"
                _ai_stats["current_tenant"] = None
                _ai_stats["current_device"] = None
                await asyncio.sleep(_LLM_WORKER_IDLE_DELAY)
                continue

            print(f"🤖 LLM worker: {len(pending)} tenant(s) need analysis")

            for tenant in pending:
                tid   = tenant["tenant_id"]
                tname = tenant["name"]
                n_dev = tenant["pending_devices"]
                need_summary = bool(tenant["needs_summary"])

                # Skip if an active per-tenant or global scan is already handling this tenant
                if tid in _scan_tasks and not _scan_tasks[tid].done():
                    print(f"  ⏭️  [{tname}] skipping — per-tenant scan in progress")
                    continue
                if _global_scan_state.get("status") == "running":
                    print(f"  ⏭️  [{tname}] skipping — global scan in progress")
                    break  # don't touch anything while global scan runs; retry later

                _ai_stats["status"] = "analyzing"
                _ai_stats["current_tenant"] = tname
                print(f"  🔬 [{tname}] {n_dev} device(s) to analyse, summary={'needed' if need_summary else 'exists'}")

                # Load full device data once (need CVEs)
                results = await loop.run_in_executor(thread_pool, db.load_tenant_results, tid)
                devices = results.get("devices", [])
                devices_by_name = {d["resource_name"]: d for d in devices}

                # ── Step 1: per-device LLM analysis ──────────────────────────
                stubs = await loop.run_in_executor(thread_pool, db.get_devices_needing_llm, tid)
                analyzed = 0

                for stub in stubs:
                    dname = stub["resource_name"]
                    dev   = devices_by_name.get(dname)
                    if not dev or not dev.get("cves"):
                        continue

                    cves     = dev["cves"]
                    verdicts = await loop.run_in_executor(thread_pool, db.get_cve_verdicts, dname)
                    fba_data = await loop.run_in_executor(thread_pool, db.get_device_fba_by_name, dname)
                    cve_key  = _analysis_cache_key(dname, cves, verdicts, fba_data)
                    from_cache = cve_key in llm_analysis_cache

                    _ai_stats["current_device"] = dname

                    if from_cache:
                        analysis = llm_analysis_cache[cve_key]
                        _ai_stats["total_cache_hits"] += 1
                        print(f"    ⚡ [{tname}] cache hit: {dname}")
                    else:
                        print(f"    🤖 [{tname}] analysing {dname} ({len(cves)} CVE(s), score {stub['highest_severity_score']:.1f})…")
                        t0 = time.time()
                        async with _llm_worker_sem:
                            analysis = await get_llm_analysis(
                                dname,
                                dev.get("resource_type", "Unknown"),
                                dev.get("os", "Unknown"),
                                cves,
                                fba_data,
                                verdicts,
                            )
                        elapsed_ms = round((time.time() - t0) * 1000)
                        _ai_stats["total_api_calls"] += 1
                        _update_ai_latency(elapsed_ms)
                        print(f"      ↳ {elapsed_ms}ms")
                        llm_analysis_cache[cve_key] = analysis
                        save_cache(LLM_ANALYSIS_CACHE_FILE, llm_analysis_cache)
                        await asyncio.sleep(_LLM_WORKER_DEVICE_DELAY)

                    await loop.run_in_executor(
                        thread_pool, db.update_device_llm_analysis, tid, dname, analysis
                    )
                    # Update local copy so estate summary sees the fresh text
                    if dname in devices_by_name:
                        devices_by_name[dname]["llm_analysis"] = analysis

                    _ai_stats["total_analyzed"] += 1
                    _ai_stats["last_activity"] = datetime.utcnow().isoformat()
                    _ai_completion_ts.append(time.time())
                    _prune_completion_ts()
                    analyzed += 1

                if analyzed:
                    print(f"  ✅ [{tname}] {analyzed} device(s) analysed")

                # ── Step 2: estate-level summary ─────────────────────────────
                if need_summary or analyzed > 0:
                    _ai_stats["current_device"] = "(estate summary)"
                    fresh_devices = list(devices_by_name.values())
                    await generate_estate_summary(tid, tname, fresh_devices)

                _ai_stats["current_device"] = None
                await asyncio.sleep(_LLM_WORKER_TENANT_DELAY)

        except Exception as e:
            _ai_stats["status"] = "error"
            _ai_stats["total_errors"] += 1
            _ai_stats["current_device"] = None
            print(f"❌ LLM back-fill worker error: {e}")
            traceback.print_exc()
            await asyncio.sleep(_LLM_WORKER_ERROR_DELAY)


# ---------------------------------------------------------------------------
# API ENDPOINTS
# ---------------------------------------------------------------------------

def _enrich_tenant(t: dict) -> dict:
    """Add local cache metadata to a NetBox tenant dict."""
    tid = str(t["id"])
    row = db.get_tenant(tid)
    scan_st = _scan_state.get(tid, {})
    redis_st = r.hgetall(f"scan:{tid}")
    status = scan_st.get("status") or redis_st.get("status") or ("complete" if row.get("scanned_at") else "idle")
    age_hours = db.get_cache_age_hours(tid)
    return {
        "id": t["id"],
        "name": t["name"],
        "slug": t.get("slug"),
        "description": t.get("description"),
        "status": status,
        "last_scan": row.get("scanned_at"),
        "device_count": row.get("total_devices", 0),
        "cache_age_hours": round(age_hours, 1) if age_hours is not None else None,
        "is_stale": age_hours is not None and age_hours >= CACHE_MAX_AGE_HOURS,
    }


# Cache: tenant_id -> (has_devices: bool, checked_at: float)
# Avoids re-checking the same tenant on every keystroke.
_tenant_has_devices_cache: dict[str, tuple[bool, float]] = {}
TENANT_DEVICE_CHECK_TTL = 3600  # re-check after 1 hour


async def _check_tenant_has_devices(tenant_id: str, client: httpx.AsyncClient, headers: dict) -> bool:
    """Return True if the tenant has at least one device or VM in NetBox."""
    now = time.time()
    cached = _tenant_has_devices_cache.get(tenant_id)
    if cached and (now - cached[1]) < TENANT_DEVICE_CHECK_TTL:
        return cached[0]

    tid = str(tenant_id)
    has = False
    try:
        for endpoint in (
            f"{NETBOX_URL}/api/dcim/devices/?tenant_id={tid}&limit=1",
            f"{NETBOX_URL}/api/virtualization/virtual-machines/?tenant_id={tid}&limit=1",
        ):
            resp = await client.get(endpoint, headers=headers, timeout=10)
            if resp.status_code == 200 and resp.json().get("count", 0) > 0:
                has = True
                break
    except Exception as e:
        print(f"  ⚠️  Device-check failed for tenant {tid}: {e}")

    _tenant_has_devices_cache[tid] = (has, now)
    return has


async def _netbox_tenant_search(q: str, limit: int, devices_only: bool = False) -> list:
    """Query NetBox tenant search API and return enriched results."""
    headers = {"Authorization": f"Token {NETBOX_TOKEN}", "Accept": "application/json"}

    # When filtering by devices_only we may need to over-fetch to fill the result
    # set after filtering, so request up to 4x and trim at the end.
    fetch_limit = min(limit * 4, 200) if devices_only else limit
    params = {"limit": fetch_limit}
    if q:
        params["q"] = q
    url = f"{NETBOX_URL}/api/tenancy/tenants/?" + urllib.parse.urlencode(params)

    try:
        async with httpx.AsyncClient(verify=False) as client:
            resp = await client.get(url, headers=headers, timeout=15)
            if resp.status_code == 401:
                raise HTTPException(status_code=502, detail="NetBox returned 401 Unauthorized — check NETBOX_TOKEN")
            if resp.status_code == 403:
                raise HTTPException(status_code=502, detail="NetBox returned 403 Forbidden — token lacks read access to tenancy")
            resp.raise_for_status()
            raw = resp.json().get("results", [])

            if devices_only and raw:
                checks = await asyncio.gather(*[
                    _check_tenant_has_devices(str(t["id"]), client, headers)
                    for t in raw
                ])
                raw = [t for t, has in zip(raw, checks) if has]

    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ NetBox tenant search failed: {e}")
        raise HTTPException(status_code=502, detail=f"Failed to reach NetBox: {str(e)}")

    return [_enrich_tenant(t) for t in raw[:limit]]


@app.get("/api/tenants/search")
async def search_tenants(q: str = "", limit: int = 50, devices_only: bool = False):
    """
    Search tenants by name/description via NetBox.
    Pass devices_only=true to exclude tenants with no devices or VMs.
    """
    return await _netbox_tenant_search(q.strip(), min(limit, 200), devices_only=devices_only)


@app.get("/api/tenants/recent")
async def recent_tenants():
    """
    Return tenants that have a local scan cache, sorted by most recently scanned.
    Used to populate the dropdown before the user starts typing.
    """
    try:
        rows = db.list_recent_tenants(limit=200)
        return [
            {
                "id": int(r["tenant_id"]) if str(r["tenant_id"]).isdigit() else r["tenant_id"],
                "name": r["name"],
                "slug": None,
                "description": None,
                "status": "complete",
                "last_scan": r["scanned_at"],
                "device_count": r["total_devices"],
                "cache_age_hours": round(db.get_cache_age_hours(r["tenant_id"]) or 0, 1),
                "is_stale": (db.get_cache_age_hours(r["tenant_id"]) or 0) >= CACHE_MAX_AGE_HOURS,
            }
            for r in rows
        ]
    except Exception as e:
        print(f"❌ Error listing recent tenants: {e}")
        return []


@app.get("/api/tenants")
async def get_tenants(q: str = "", limit: int = 50, devices_only: bool = False):
    """Legacy / compat endpoint. Delegates to search."""
    return await _netbox_tenant_search(q.strip(), min(limit, 200), devices_only=devices_only)


@app.post("/api/scan/global")
async def trigger_global_scan():
    """Start a global scan of all tenants. Ignored if one is already running."""
    global _global_scan_task
    if _global_scan_task and not _global_scan_task.done():
        return {"status": "running", "message": "Global scan already in progress."}
    _global_scan_task = asyncio.create_task(run_global_scan())
    return {"status": "started", "message": "Global scan started."}


@app.get("/api/scan/global/status")
async def get_global_scan_status():
    """Return current global scan state including phase timings and elapsed time."""
    state = dict(_global_scan_state)
    if state["status"] == "running" and state["started_at"]:
        state["elapsed_seconds"] = round(time.time() - datetime.fromisoformat(state["started_at"]).timestamp(), 1)
    return state


@app.get("/api/scan/global/stream")
async def stream_global_scan():
    """SSE stream of global scan progress events."""
    q: asyncio.Queue = asyncio.Queue(maxsize=200)
    _global_sse_subscribers.append(q)

    async def event_gen():
        initial = dict(_global_scan_state)
        if initial.get("status") == "running" and initial.get("started_at"):
            initial["elapsed_seconds"] = round(time.time() - datetime.fromisoformat(initial["started_at"]).timestamp(), 1)
        yield f"data: {json_dumps({'type': 'progress', 'state': initial})}\n\n"

        try:
            while True:
                try:
                    msg = await asyncio.wait_for(q.get(), timeout=30.0)
                    yield f"data: {json_dumps(msg)}\n\n"
                    q.task_done()
                    if msg.get("type") == "complete":
                        break
                except asyncio.TimeoutError:
                    state = dict(_global_scan_state)
                    if state.get("status") == "running" and state.get("started_at"):
                        state["elapsed_seconds"] = round(time.time() - datetime.fromisoformat(state["started_at"]).timestamp(), 1)
                    yield f"data: {json_dumps({'type': 'progress', 'state': state})}\n\n"
        finally:
            try:
                _global_sse_subscribers.remove(q)
            except ValueError:
                pass

    return StreamingResponse(
        event_gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.post("/api/scan/{tenant_id}")
async def trigger_scan(tenant_id: str, tenant_name: str = "", force: bool = False):
    """
    Trigger a CVE scan for a tenant.
    - force=true: always start a new scan even if cache is fresh.
    - If cache is fresh (< 24h): return cached data with status 200.
    - If cache is stale (>= 24h): start background scan, return 202 with stale-cache notice.
    - If no cache: start scan, return 202.
    """
    tid = str(tenant_id)

    # Resolve tenant name if not provided
    if not tenant_name:
        try:
            headers = {"Authorization": f"Token {NETBOX_TOKEN}", "Accept": "application/json"}
            async with httpx.AsyncClient(verify=False) as client:
                resp = await client.get(f"{NETBOX_URL}/api/tenancy/tenants/{tid}/", headers=headers, timeout=10)
                resp.raise_for_status()
                tenant_name = resp.json().get("name", f"Tenant {tid}")
        except Exception:
            tenant_name = f"Tenant {tid}"

    # Already running
    if tid in _scan_tasks and not _scan_tasks[tid].done():
        return {"status": "running", "message": "Scan already in progress."}

    age_hours = get_cache_age_hours(tid)

    if not force and age_hours is not None and age_hours < CACHE_MAX_AGE_HOURS:
        return {"status": "cached", "message": f"Cache is fresh ({age_hours:.1f}h old). Using cached results."}

    stale = age_hours is not None and age_hours >= CACHE_MAX_AGE_HOURS
    _scan_queues[tid] = asyncio.Queue()
    task = asyncio.create_task(run_tenant_scan(tid, tenant_name))
    _scan_tasks[tid] = task

    if stale:
        return {
            "status": "refreshing",
            "message": f"Cache is {age_hours:.0f}h old. Refreshing in background — current results still available."
        }
    return {"status": "started", "message": "Scan started."}


@app.get("/api/scan/{tenant_id}/status")
async def get_scan_status(tenant_id: str):
    tid = str(tenant_id)
    scan_st = _scan_state.get(tid, {})
    redis_st = r.hgetall(f"scan:{tid}")

    status = scan_st.get("status") or redis_st.get("status") or "idle"
    scanned = int(scan_st.get("scanned") or redis_st.get("scanned") or 0)
    total = int(scan_st.get("total") or redis_st.get("total") or 0)
    started_at = scan_st.get("started_at") or redis_st.get("started_at")

    cached = load_tenant_results(tid)
    if status == "idle" and cached.get("scanned_at"):
        status = "complete"

    return {
        "status": status,
        "scanned": scanned,
        "total": total,
        "started_at": started_at,
        "last_scan": cached.get("scanned_at"),
        "is_stale": (get_cache_age_hours(tid) or 0) >= CACHE_MAX_AGE_HOURS,
    }


@app.get("/api/results/{tenant_id}")
async def get_results(tenant_id: str):
    """Return full cached results for a tenant."""
    cached = load_tenant_results(str(tenant_id))
    if not cached:
        return {"devices": [], "scanned_at": None}
    return cached


@app.get("/api/results/{tenant_id}/summary")
async def get_summary(tenant_id: str):
    """Return the cached estate LLM summary for a tenant."""
    summary = load_tenant_summary(str(tenant_id))
    if not summary:
        return None
    return summary


@app.get("/api/results/{tenant_id}/stream")
async def stream_results(tenant_id: str):
    """
    SSE endpoint for streaming incremental scan results.
    - If a scan is running: streams live updates then closes on completion.
    - If no scan is running: immediately flushes cached results and closes.
    """
    tid = str(tenant_id)

    async def event_generator():
        scan_running = tid in _scan_tasks and not _scan_tasks[tid].done()

        if not scan_running:
            # No active scan — stream the cached results and close
            cached = load_tenant_results(tid)
            for device in cached.get("devices", []):
                yield f"data: {json_dumps({'type': 'device', 'data': device})}\n\n"
            yield f"data: {json_dumps({'type': 'complete'})}\n\n"
            return

        # Active scan — subscribe to the queue
        queue = _scan_queues.get(tid)
        if not queue:
            yield f"data: {json_dumps({'type': 'complete'})}\n\n"
            return

        while True:
            try:
                msg = await asyncio.wait_for(queue.get(), timeout=30.0)
                yield f"data: {json_dumps(msg)}\n\n"
                queue.task_done()
                if msg.get("type") == "complete":
                    break
            except asyncio.TimeoutError:
                # Keep-alive ping
                yield ": ping\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}
    )


@app.get("/api/stats")
async def get_estate_stats():
    """Aggregate statistics across all scanned tenants for the leaderboard landing page."""
    loop = asyncio.get_running_loop()
    stats, top_cves, top_platforms, top_types, severity = await asyncio.gather(
        loop.run_in_executor(thread_pool, db.get_estate_stats),
        loop.run_in_executor(thread_pool, db.get_top_cves, 20),
        loop.run_in_executor(thread_pool, db.get_top_platforms, 15),
        loop.run_in_executor(thread_pool, db.get_top_device_types, 15),
        loop.run_in_executor(thread_pool, db.get_severity_breakdown),
    )
    return {
        "estate": stats,
        "top_cves": top_cves,
        "top_platforms": top_platforms,
        "top_device_types": top_types,
        "severity_breakdown": severity,
    }


_ILLEGAL_CHARS_RE = re.compile(r'[\x00-\x08\x0b-\x0c\x0e-\x1f]')

def _xlsx_str(v) -> str | None:
    """Strip XML-illegal control characters from a string before writing to xlsx."""
    if v is None:
        return None
    return _ILLEGAL_CHARS_RE.sub('', str(v))


@app.get("/api/ai/stats")
async def get_ai_stats():
    """Return live LLM back-fill worker metrics."""
    _prune_completion_ts()
    total_calls = _ai_stats["total_api_calls"] + _ai_stats["total_cache_hits"]
    cache_rate = round(100 * _ai_stats["total_cache_hits"] / total_calls, 1) if total_calls else None
    return {
        **_ai_stats,
        "cache_hit_rate_pct": cache_rate,
        "total_llm_calls": total_calls,
    }


@app.get("/api/scan-history")
async def get_scan_history_endpoint(limit: int = 20):
    """Return the most recent scan snapshots for trend analysis."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(thread_pool, db.get_scan_history, min(limit, 50))


@app.get("/api/scan-trends")
async def get_scan_trends_endpoint():
    """Return the two most recent scan snapshots plus computed deltas."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(thread_pool, db.get_scan_trends)


@app.get("/api/config/vendors")
async def get_vendors_endpoint(tenant_ids: str = ""):
    """Return distinct platform/vendor names, optionally filtered to specific tenants.

    tenant_ids: comma-separated list of tenant_id values; empty string = all tenants.
    Used by the notification form to dynamically populate the vendor filter list.
    """
    tids = [t.strip() for t in tenant_ids.split(",") if t.strip()] if tenant_ids else []
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(thread_pool, db.get_vendors_for_tenants, tids)


def _write_cve_data_sheet(ws, rows: list):
    """Populate the CVE Data worksheet."""
    from openpyxl.styles import Font, PatternFill, Alignment
    headers = [
        "Client Name", "Device Name", "PON", "Platform", "Device Type",
        "Current Firmware", "NVD Min-Fix Version", "Eng Recommended Version",
        "Serial Number", "Device CVE Score", "Number of Vulnerabilities",
    ]
    hdr_fill = PatternFill(start_color="1F3864", end_color="1F3864", fill_type="solid")
    hdr_font = Font(color="FFFFFF", bold=True)
    for col, h in enumerate(headers, 1):
        cell = ws.cell(row=1, column=col, value=h)
        cell.font = hdr_font
        cell.fill = hdr_fill
        cell.alignment = Alignment(horizontal="center", vertical="center")
    ws.row_dimensions[1].height = 20
    # Highlight the engineering recommended column header in a distinct colour
    eng_hdr = ws.cell(row=1, column=8)
    eng_hdr.fill = PatternFill(start_color="1A3A5C", end_color="1A3A5C", fill_type="solid")
    for i, row in enumerate(rows, 2):
        ws.cell(row=i, column=1,  value=_xlsx_str(row.get("tenant_name")))
        ws.cell(row=i, column=2,  value=_xlsx_str(row.get("resource_name")))
        ws.cell(row=i, column=3,  value=_xlsx_str(row.get("pon")))
        ws.cell(row=i, column=4,  value=_xlsx_str(row.get("platform_name")))
        ws.cell(row=i, column=5,  value=_xlsx_str(row.get("device_type")))
        ws.cell(row=i, column=6,  value=_xlsx_str(row.get("current_firmware")))
        ws.cell(row=i, column=7,  value=_xlsx_str(row.get("recommended_version")))
        gia_cell = ws.cell(row=i, column=8, value=_xlsx_str(row.get("gia_recommended_version")))
        if row.get("gia_recommended_version"):
            gia_cell.font = Font(color="5B9BD5", bold=True)
        ws.cell(row=i, column=9,  value=_xlsx_str(row.get("serial")))
        score = round(row.get("cve_score") or 0.0, 1)
        sc = ws.cell(row=i, column=10, value=score)
        ws.cell(row=i, column=11, value=row.get("cve_count", 0))
        if score >= 9.0:
            sc.fill = PatternFill(start_color="FF0000", end_color="FF0000", fill_type="solid")
            sc.font = Font(color="FFFFFF", bold=True)
        elif score >= 7.0:
            sc.fill = PatternFill(start_color="FF8C00", end_color="FF8C00", fill_type="solid")
            sc.font = Font(color="FFFFFF")
        elif score >= 4.0:
            sc.fill = PatternFill(start_color="FFD700", end_color="FFD700", fill_type="solid")
    for col, width in enumerate([20, 30, 15, 20, 25, 20, 22, 24, 20, 18, 22], 1):
        ws.column_dimensions[ws.cell(row=1, column=col).column_letter].width = width
    ws.freeze_panes = "A2"


def _write_dashboard_sheet(ws, stats: dict, leaderboard: list):
    """Populate the Dashboard worksheet with estate stats and top-10 leaderboard."""
    from openpyxl.styles import Font, PatternFill, Alignment
    from openpyxl.utils import get_column_letter
    NAVY  = PatternFill(start_color="1F3864", end_color="1F3864", fill_type="solid")
    SECT  = PatternFill(start_color="2D2D2D", end_color="2D2D2D", fill_type="solid")
    ALT   = PatternFill(start_color="F2F2F2", end_color="F2F2F2", fill_type="solid")

    def hdr(row, col, val, fill=NAVY, sz=13, bold=True, span=10, color="FFFFFF"):
        c = ws.cell(row=row, column=col, value=val)
        c.font = Font(color=color, bold=bold, size=sz)
        c.fill = fill
        c.alignment = Alignment(horizontal="left", vertical="center", wrap_text=False)
        if span > 1:
            ws.merge_cells(start_row=row, start_column=col, end_row=row, end_column=col + span - 1)
        ws.row_dimensions[row].height = 22 if sz >= 13 else 18
        return c

    def kv(row, key, val, val_color="000000", bold_val=False):
        lc = ws.cell(row=row, column=1, value=key)
        lc.font = Font(color="444444", size=10)
        lc.alignment = Alignment(horizontal="left", vertical="center")
        vc = ws.cell(row=row, column=2, value=val)
        vc.font = Font(color=val_color, bold=bold_val, size=11)
        vc.alignment = Alignment(horizontal="left", vertical="center")
        ws.row_dimensions[row].height = 16

    # ── Title ─────────────────────────────────────────────────────────
    hdr(1, 1, "DEFENSE HALO — Estate Security Summary", sz=14)
    kv(2, "Generated", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"))
    ws.row_dimensions[3].height = 8  # spacer

    # ── Estate Stats ──────────────────────────────────────────────────
    hdr(4, 1, "ESTATE SUMMARY", fill=SECT, sz=10, color="6EE7B7")
    row = 5
    kv(row,     "Total Clients",       stats.get("total_tenants", 0)); row += 1
    kv(row,     "Total Devices",       stats.get("total_devices", 0)); row += 1
    kv(row,     "  Physical Devices",  stats.get("physical_devices", 0)); row += 1
    kv(row,     "  Virtual Machines",  stats.get("virtual_machines", 0)); row += 1
    vuln = stats.get("vulnerable_devices", 0)
    total = stats.get("total_devices", 1) or 1
    kv(row, "Vulnerable Devices", f"{vuln:,}  ({round(100*vuln/total)}% of estate)", val_color="FB923C"); row += 1
    crit = stats.get("critical_devices", 0)
    kv(row, "Critical Devices",   crit, val_color="EF4444" if crit else "4ADE80", bold_val=crit > 0); row += 1
    kv(row, "Total CVE Instances", f"{stats.get('total_cve_instances', 0):,}", val_color="FBBF24"); row += 1
    peak = stats.get("max_score") or 0.0
    peak_color = "EF4444" if peak >= 9 else "FB923C" if peak >= 7 else "FBBF24" if peak >= 4 else "4ADE80"
    kv(row, "Peak CVE Score", f"{peak:.1f}", val_color=peak_color, bold_val=True); row += 1
    ws.row_dimensions[row].height = 8  # spacer; row += 1

    # ── Leaderboard top 10 ────────────────────────────────────────────
    hdr(row + 1, 1, "TOP 10 CLIENTS BY RISK", fill=SECT, sz=10, color="6EE7B7")
    row += 2
    lb_headers = ["#", "Client", "Devices", "Vulnerable", "Vuln %", "CVE Score", "Risk Posture", "Trend", "Last Scan"]
    for col, h in enumerate(lb_headers, 1):
        c = ws.cell(row=row, column=col, value=h)
        c.font = Font(color="FFFFFF", bold=True, size=10)
        c.fill = NAVY
        c.alignment = Alignment(horizontal="center" if col != 2 else "left", vertical="center")
    ws.row_dimensions[row].height = 18
    row += 1

    for rank, lb in enumerate(leaderboard[:10], 1):
        score = lb.get("max_score") or 0.0
        srow = ws.cell(row=row, column=1, value=rank)
        srow.alignment = Alignment(horizontal="center")
        ws.cell(row=row, column=2, value=_xlsx_str(lb.get("name", "")))
        ws.cell(row=row, column=3, value=lb.get("total_devices", 0)).alignment = Alignment(horizontal="center")
        ws.cell(row=row, column=4, value=lb.get("vulnerable_devices", 0)).alignment = Alignment(horizontal="center")
        ws.cell(row=row, column=5, value=f"{lb.get('vuln_pct') or 0:.0f}%").alignment = Alignment(horizontal="center")
        sc = ws.cell(row=row, column=6, value=round(score, 1))
        sc.font = Font(bold=True, color="EF4444" if score >= 9 else "FB923C" if score >= 7 else "FBBF24" if score >= 4 else "4ADE80")
        sc.alignment = Alignment(horizontal="center")
        ws.cell(row=row, column=7, value=_xlsx_str(lb.get("risk_posture", "—"))).alignment = Alignment(horizontal="center")
        ws.cell(row=row, column=8, value=_xlsx_str(lb.get("trend", "—"))).alignment = Alignment(horizontal="center")
        age = lb.get("scanned_at", "")
        if age:
            try:
                h_ = (datetime.now(timezone.utc).replace(tzinfo=None) - datetime.fromisoformat(age).replace(tzinfo=None)).total_seconds() / 3600
                age = f"{round(h_)}h ago" if h_ < 24 else f"{round(h_/24)}d ago"
            except Exception:
                age = "—"
        ws.cell(row=row, column=9, value=age).alignment = Alignment(horizontal="center")
        row_fill = ALT if rank % 2 == 0 else None
        if row_fill:
            for col in range(1, 10):
                ws.cell(row=row, column=col).fill = row_fill
        ws.row_dimensions[row].height = 16
        row += 1

    # ── Column widths ─────────────────────────────────────────────────
    for col, width in enumerate([25, 28, 10, 12, 8, 11, 14, 10, 14], 1):
        ws.column_dimensions[get_column_letter(col)].width = width


def _build_excel(rows: list, stats: dict | None = None, leaderboard: list | None = None) -> bytes:
    from io import BytesIO
    import openpyxl

    wb = openpyxl.Workbook()
    first_ws = wb.active
    assert first_ws is not None  # openpyxl always creates an initial sheet

    if stats is not None and leaderboard is not None:
        first_ws.title = "Dashboard"
        _write_dashboard_sheet(first_ws, stats, leaderboard)
        ws_data = wb.create_sheet("CVE Data")
    else:
        first_ws.title = "CVE Data"
        ws_data = first_ws

    _write_cve_data_sheet(ws_data, rows)

    buf = BytesIO()
    wb.save(buf)
    return buf.getvalue()


@app.get("/api/export/all")
async def export_all_tenants():
    """Download an Excel file of all devices across every scanned tenant (2-sheet: Dashboard + CVE Data)."""
    loop = asyncio.get_running_loop()
    rows, stats, leaderboard = await asyncio.gather(
        loop.run_in_executor(thread_pool, db.get_export_rows, None),
        loop.run_in_executor(thread_pool, db.get_estate_stats),
        loop.run_in_executor(thread_pool, db.get_leaderboard, 10, 0),
    )
    xlsx = await loop.run_in_executor(thread_pool, _build_excel, rows, stats, leaderboard)
    fname = f"cve_export_all_{datetime.now(timezone.utc).strftime('%Y%m%d')}.xlsx"
    return Response(
        content=xlsx,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f"attachment; filename={fname}"},
    )


@app.get("/api/export/tenant/{tenant_id}")
async def export_tenant(tenant_id: str):
    """Download an Excel file of devices for a single tenant (CVE Data only)."""
    loop = asyncio.get_running_loop()
    rows = await loop.run_in_executor(thread_pool, db.get_export_rows, str(tenant_id))
    if not rows:
        raise HTTPException(status_code=404, detail="No data found for this tenant.")
    xlsx = await loop.run_in_executor(thread_pool, _build_excel, rows)
    safe = re.sub(r'[^\w\-]', '_', rows[0].get("tenant_name", tenant_id))
    fname = f"cve_export_{safe}_{datetime.now(timezone.utc).strftime('%Y%m%d')}.xlsx"
    return Response(
        content=xlsx,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f"attachment; filename={fname}"},
    )


# ---------------------------------------------------------------------------
# Drilldown endpoints (dashboard widget click-through)
# ---------------------------------------------------------------------------

_DRILLDOWN_FETCHERS = {
    "severity":      lambda v: db.get_devices_by_severity(v),
    "platform":      lambda v: db.get_devices_by_platform(v),
    "cve":           lambda v: db.get_devices_by_cve(v),
    "clients":       lambda _: db.get_all_clients_detail(),
    "all_devices":   lambda _: db.get_all_devices_list(),
    "vulnerable":    lambda _: db.get_vulnerable_devices(),
    "critical":      lambda _: db.get_critical_devices(),
    "cve_instances": lambda _: db.get_all_cve_instances(),
    "peak_score":    lambda _: db.get_devices_at_peak_score(),
}


@app.get("/api/drilldown")
async def drilldown(type: str, value: str = ""):
    """Return data for a dashboard widget drilldown."""
    fetcher = _DRILLDOWN_FETCHERS.get(type)
    if not fetcher:
        raise HTTPException(status_code=400, detail=f"Unknown drilldown type: {type}")
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(thread_pool, fetcher, value)


def _build_generic_excel(rows: list, columns: list, title: str = "") -> bytes:
    from io import BytesIO
    import openpyxl
    from openpyxl.styles import Font, PatternFill, Alignment
    from openpyxl.utils import get_column_letter

    wb = openpyxl.Workbook()
    ws = wb.active
    assert ws is not None
    ws.title = title[:31] if title else "Data"

    hdr_fill = PatternFill(start_color="1F3864", end_color="1F3864", fill_type="solid")
    hdr_font = Font(color="FFFFFF", bold=True)
    for col_idx, (header, _, width) in enumerate(columns, 1):
        c = ws.cell(row=1, column=col_idx, value=header)
        c.font = hdr_font
        c.fill = hdr_fill
        c.alignment = Alignment(horizontal="center", vertical="center")
        ws.column_dimensions[get_column_letter(col_idx)].width = width
    ws.row_dimensions[1].height = 20
    ws.freeze_panes = "A2"

    for ri, row in enumerate(rows, 2):
        for col_idx, (_, key, _) in enumerate(columns, 1):
            val = row.get(key)
            if isinstance(val, float):
                val = round(val, 1)
            ws.cell(row=ri, column=col_idx, value=_xlsx_str(val) if isinstance(val, str) else val)

    buf = BytesIO()
    wb.save(buf)
    return buf.getvalue()


_CLIENT_COLUMNS = [
    ("Client", "name", 30), ("Devices", "total_devices", 12),
    ("Vulnerable", "vulnerable_devices", 14), ("Vuln %", "vuln_pct", 10),
    ("CVE Score", "max_score", 12), ("Risk", "risk_posture", 14),
    ("Trend", "trend", 10), ("Last Scan", "scanned_at", 22),
]

_CVE_INSTANCE_COLUMNS = [
    ("Client", "tenant_name", 25), ("Device", "resource_name", 30),
    ("Platform", "platform_name", 18), ("Firmware", "current_firmware", 18),
    ("CVE ID", "cve_id", 20), ("Score", "score", 10),
    ("Severity", "severity", 12), ("Description", "description", 60),
]


@app.get("/api/export/drilldown")
async def export_drilldown(type: str, value: str = ""):
    """Download a single-sheet XLS for a drilldown query."""
    fetcher = _DRILLDOWN_FETCHERS.get(type)
    if not fetcher:
        raise HTTPException(status_code=400, detail=f"Unknown drilldown type: {type}")
    loop = asyncio.get_running_loop()
    rows = await loop.run_in_executor(thread_pool, fetcher, value)

    if type == "clients":
        xlsx = await loop.run_in_executor(thread_pool, _build_generic_excel, rows, _CLIENT_COLUMNS, "Clients")
    elif type == "cve_instances":
        xlsx = await loop.run_in_executor(thread_pool, _build_generic_excel, rows, _CVE_INSTANCE_COLUMNS, "CVE Instances")
    else:
        xlsx = await loop.run_in_executor(thread_pool, _build_excel, rows)

    safe = re.sub(r'[^\w\-]', '_', value or type)
    fname = f"drilldown_{type}_{safe}_{datetime.now(timezone.utc).strftime('%Y%m%d')}.xlsx"
    return Response(
        content=xlsx,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f"attachment; filename={fname}"},
    )


@app.get("/api/leaderboard")
async def get_leaderboard(limit: int = 100, min_devices: int = 1, score: str = "cvss"):
    """
    Return tenants ranked by worst security posture (highest CVE score, then most vulnerable devices).
    Useful for prioritising remediation across the estate.

    score=effective ranks by the config-aware score, which ignores CVEs a device's
    running config has ruled out (not_applicable / mitigated). Every row carries
    both max_score (raw CVSS) and effective_max_score regardless.
    """
    return db.get_leaderboard(limit=min(limit, 1000), min_devices=min_devices, score=score)


@app.get("/api/tenants")
async def get_all_tenants():
    """Return every tenant row alphabetically — no limit, no device-count filter."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(thread_pool, db.get_all_tenants)


@app.get("/api/changelog")
async def get_changelog():
    """Return the changelog.json file for the in-app release notes viewer."""
    changelog_path = Path(__file__).parent / "changelog.json"
    if not changelog_path.exists():
        return []
    return json_loads(changelog_path.read_text())


# Status endpoint (legacy compat, also used by frontend health check)
@app.get("/status")
async def get_status():
    return {"service": "Defense Halo Customer CVE Analyzer", "status": "ok"}


@app.get("/api/gia/status")
async def gia_status():
    """Dump the GIA version cache — readable any time after a scan completes."""
    import gia_client as _gia
    import time as _time
    cache = _gia._cache
    now = _time.monotonic()
    rows = []
    for key, (result, cached_at) in sorted(cache.items()):
        age_s = int(now - cached_at)
        rows.append({
            "platform_key": key,
            "gia_recommended_version": (result or {}).get("gia_recommended_version"),
            "gia_component": (result or {}).get("gia_component"),
            "matched": result is not None and bool((result or {}).get("gia_recommended_version")),
            "age_seconds": age_s,
        })
    matched = sum(1 for r in rows if r["matched"])
    return {
        "total_cached": len(rows),
        "matched": matched,
        "no_match": len(rows) - matched,
        "cache_ttl_hours": _gia.GIA_CACHE_TTL_S / 3600,
        "api_key_set": bool(_gia.GIA_API_KEY),
        "base_url": _gia.GIA_BASE_URL,
        "entries": rows,
    }


# ---------------------------------------------------------------------------
# Notification config endpoints
# ---------------------------------------------------------------------------

@app.get("/api/config/notifications")
async def list_notifications():
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(thread_pool, db.list_notifications)


@app.post("/api/config/notifications")
async def create_notification(payload: dict):
    loop = asyncio.get_running_loop()
    saved = await loop.run_in_executor(thread_pool, db.save_notification, payload)
    return saved


@app.put("/api/config/notifications/{notification_id}")
async def update_notification(notification_id: str, payload: dict):
    payload["id"] = notification_id
    loop = asyncio.get_running_loop()
    saved = await loop.run_in_executor(thread_pool, db.save_notification, payload)
    if saved is None:
        raise HTTPException(status_code=404, detail="Notification not found")
    return saved


@app.delete("/api/config/notifications/{notification_id}")
async def delete_notification(notification_id: str):
    loop = asyncio.get_running_loop()
    deleted = await loop.run_in_executor(thread_pool, db.delete_notification, notification_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Notification not found")
    return {"ok": True}


async def _build_notification_payload(cfg: dict, loop) -> tuple:
    """Build (xlsx, stats, leaderboard) for a notification, respecting its filters."""
    filter_tenant_ids = cfg.get("filter_tenant_ids") or []
    filter_platforms  = cfg.get("filter_platforms") or []

    def get_rows():
        return db.get_export_rows(
            tenant_ids=filter_tenant_ids or None,
            platforms=filter_platforms or None,
        )

    rows        = await loop.run_in_executor(thread_pool, get_rows)
    stats       = await loop.run_in_executor(thread_pool, db.get_estate_stats)
    leaderboard = await loop.run_in_executor(thread_pool, db.get_leaderboard, 20, 0)

    # Filter leaderboard to selected tenants only (platforms don't affect tenant ranking)
    if filter_tenant_ids:
        tid_set = set(filter_tenant_ids)
        leaderboard = [r for r in leaderboard if r["tenant_id"] in tid_set]

    xlsx = await loop.run_in_executor(thread_pool, _build_excel, rows, stats, leaderboard)
    return xlsx, stats, leaderboard


@app.post("/api/config/notifications/{notification_id}/test")
async def test_notification(notification_id: str):
    """Send a test email immediately using this notification's config."""
    loop = asyncio.get_running_loop()
    cfg = await loop.run_in_executor(thread_pool, db.get_notification, notification_id)
    if cfg is None:
        raise HTTPException(status_code=404, detail="Notification not found")
    try:
        xlsx, stats, leaderboard = await _build_notification_payload(cfg, loop)
        await loop.run_in_executor(
            thread_pool, email_report.send_report_email, cfg, xlsx, stats, leaderboard
        )
        return {"ok": True, "message": "Test email sent successfully."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ---------------------------------------------------------------------------
# Notification scheduler
# ---------------------------------------------------------------------------

def _should_fire(cfg: dict, now: datetime) -> bool:
    """Return True if this notification is due to send right now."""
    if not cfg.get("enabled"):
        return False

    time_str = (cfg.get("schedule_time_utc") or "00:00").strip()
    try:
        h, m = [int(x) for x in time_str.split(":")]
    except ValueError:
        return False

    if now.hour != h or now.minute != m:
        return False

    freq = (cfg.get("schedule_frequency") or "daily").lower()
    if freq == "daily":
        pass  # time match is sufficient
    elif freq == "weekly":
        dow = int(cfg.get("schedule_day_of_week") or 1)
        if now.isoweekday() != dow:
            return False
    elif freq == "monthly":
        dom = int(cfg.get("schedule_day_of_month") or 1)
        if now.day != dom:
            return False
    else:
        return False

    # Avoid double-firing within the same minute
    last = cfg.get("last_sent_at")
    if last:
        try:
            last_dt = datetime.fromisoformat(last)
            if last_dt.tzinfo is None:
                last_dt = last_dt.replace(tzinfo=timezone.utc)
            if (now - last_dt).total_seconds() < 90:
                return False
        except (ValueError, TypeError):
            pass

    return True


async def notification_scheduler():
    """Background task: check every 60s whether any notification is due."""
    print("✅ Notification scheduler started.")
    while True:
        await asyncio.sleep(60)
        try:
            loop = asyncio.get_running_loop()
            notifications = await loop.run_in_executor(thread_pool, db.list_notifications)
            now = datetime.now(timezone.utc).replace(second=0, microsecond=0)

            for cfg in notifications:
                if not _should_fire(cfg, now):
                    continue

                nid  = cfg["id"]
                name = cfg.get("name", nid)
                print(f"📧 Sending scheduled notification: {name}")
                try:
                    xlsx, stats, leaderboard = await _build_notification_payload(cfg, loop)
                    await loop.run_in_executor(
                        thread_pool, email_report.send_report_email, cfg, xlsx, stats, leaderboard
                    )
                    sent_at = datetime.now(timezone.utc).isoformat()
                    await loop.run_in_executor(
                        thread_pool, db.update_notification_sent, nid, sent_at
                    )
                    print(f"  ✅ Notification '{name}' sent at {sent_at}")
                except Exception as e:
                    print(f"  ❌ Notification '{name}' failed: {e}")
        except Exception as e:
            print(f"❌ Notification scheduler error: {e}")


async def daily_scan_scheduler():
    """Background task: trigger a global scan once per day at DAILY_SCAN_TIME_UTC."""
    try:
        h, m = [int(x) for x in DAILY_SCAN_TIME_UTC.strip().split(":")]
    except ValueError:
        print(f"⚠️  Invalid DAILY_SCAN_TIME_UTC '{DAILY_SCAN_TIME_UTC}', defaulting to 02:00")
        h, m = 2, 0

    print(f"✅ Daily scan scheduler started (fires at {h:02d}:{m:02d} UTC).")
    while True:
        await asyncio.sleep(30)
        now = datetime.now(timezone.utc)
        if now.hour != h or now.minute != m:
            continue

        global _global_scan_task
        if _global_scan_task and not _global_scan_task.done():
            continue

        print(f"🔄 Daily scheduled scan triggered at {now.strftime('%Y-%m-%d %H:%M UTC')}")
        _global_scan_task = asyncio.create_task(run_global_scan())

        # Sleep past the current minute to avoid re-triggering
        await asyncio.sleep(60)


async def fba_enrichment_worker():
    """
    Background task: keep every Fortinet device's FBA audit data current.

    One cycle = pull FBA's complete inventory listing (≈11 requests for ~10k
    configs), match all our Fortinet devices against it locally, then fetch
    the full audit only for devices whose FBA last_analyzed_at changed since we
    stored it. Devices absent from the listing are "not found" at no cost.
    Steady state is a dozen requests per cycle. Pauses while a global scan runs.
    """
    if not FBA_ENABLED:
        print("ℹ️  FBA enrichment disabled (FBA_ENABLED=false).")
        return

    print("✅ FBA enrichment worker started.")
    await asyncio.sleep(30)  # let startup settle
    loop = asyncio.get_running_loop()

    while True:
        try:
            if _global_scan_state.get("status") == "running":
                await asyncio.sleep(30)
                continue

            t0 = time.time()
            async with httpx.AsyncClient(verify=fba_client.FBA_VERIFY_SSL) as client:
                items = await fba_client.list_all_inventory(client)
                if items is None:
                    err = fba_client.last_error or "unknown error"
                    print(f"❌ FBA: could not fetch the inventory listing — {err}"
                          + ("  → FBA's certificate is issued by the corporate CA; set FBA_VERIFY_SSL to the CA bundle path."
                             if "CERTIFICATE_VERIFY_FAILED" in err else "")
                          + f"  Retrying in {FBA_RETRY_HOURS}h.")
                    fba_client.progress = {"aborted": err, "started_at": datetime.now(timezone.utc).isoformat()}
                    await asyncio.sleep(FBA_RETRY_HOURS * 3600)
                    continue

                devices = await loop.run_in_executor(thread_pool, db.get_fortinet_devices_for_fba)
                to_fetch, not_found = fba_client.plan_enrichment(devices, items)
                scanned_at = datetime.now(timezone.utc).isoformat()
                fba_client.progress = {"total": len(to_fetch), "done": 0, "found": 0, "not_found": len(not_found),
                                       "failed": 0, "listing_items": len(items), "fortinet_devices": len(devices),
                                       "started_at": scanned_at, "aborted": None}
                print(f"🔍 FBA: listing has {len(items)} configs; {len(devices)} Fortinet devices — "
                      f"{len(to_fetch)} audits to fetch (new or changed), {len(not_found)} not in FBA, "
                      f"{len(devices) - len(to_fetch) - len(not_found)} already current ({time.time() - t0:.1f}s)")

                for dev in not_found:
                    await loop.run_in_executor(thread_pool, db.update_device_fba, dev["id"], None, scanned_at)

                done = found = failed = requeued = 0
                for dev, nodes in to_fetch:
                    if _global_scan_state.get("status") == "running":
                        print("  FBA: pausing — global scan started")
                        break
                    data = await fba_client.fetch_details(client, nodes)
                    done += 1
                    if data is fba_client.LOOKUP_FAILED:
                        failed += 1
                        await loop.run_in_executor(thread_pool, db.mark_fba_lookup_failed, dev["id"], scanned_at)
                        if failed >= 20 and found == 0:
                            print(f"❌ FBA: aborting — first {failed} detail fetches all failed: {fba_client.last_error}")
                            fba_client.progress["aborted"] = fba_client.last_error
                            break
                    else:
                        if await loop.run_in_executor(thread_pool, db.update_device_fba, dev["id"], data, scanned_at):
                            requeued += 1
                        if data is not None:
                            found += 1
                    fba_client.progress.update(done=done, found=found, failed=failed)
                    if done % 100 == 0:
                        print(f"  FBA: {done}/{len(to_fetch)} audits fetched — {found} found, {failed} failed"
                              + (f" | last error: {fba_client.last_error}" if failed else ""))

            print(f"✅ FBA: cycle complete in {time.time() - t0:.0f}s — {done} audits fetched ({found} found, "
                  f"{failed} failed), {len(not_found)} marked not in FBA, {requeued} AI analyses queued; "
                  f"{fba_client.stats['requests']} FBA requests so far. Next cycle in {FBA_SYNC_MINUTES}m.")

        except Exception as e:
            print(f"❌ FBA enrichment worker error: {e}")
            traceback.print_exc()

        await asyncio.sleep(FBA_SYNC_MINUTES * 60)


@app.get("/api/device/{resource_name}/fba")
async def get_device_fba(resource_name: str):
    """Return stored FBA config-analysis data for a device by name."""
    loop = asyncio.get_running_loop()
    data = await loop.run_in_executor(thread_pool, db.get_device_fba_by_name, resource_name)
    if data is None:
        raise HTTPException(status_code=404, detail="Device not found.")
    return data


@app.post("/api/device/{resource_name}/fba/refresh")
async def refresh_device_fba(resource_name: str):
    """Look this one device up in FBA right now (instead of waiting for the
    enrichment worker) and return the stored result. When the lookup fails the
    reason is included as fba_lookup_error — e.g. a certificate-verification
    failure, which means FBA_VERIFY_SSL needs to point at the corporate CA bundle."""
    loop = asyncio.get_running_loop()
    ids = await loop.run_in_executor(thread_pool, db.get_device_ids_by_name, resource_name)
    if not ids:
        raise HTTPException(status_code=404, detail="Device not found.")
    fba_client.last_error = None
    data = (await fba_client.fetch_configs_chunk([resource_name], 1)).get(resource_name)
    now = datetime.now(timezone.utc).isoformat()
    failed = data is fba_client.LOOKUP_FAILED
    for device_id in ids:
        if failed:
            await loop.run_in_executor(thread_pool, db.mark_fba_lookup_failed, device_id, now)
        else:
            await loop.run_in_executor(thread_pool, db.update_device_fba, device_id, data, now)
    out = await loop.run_in_executor(thread_pool, db.get_device_fba_by_name, resource_name)
    if failed:
        out["fba_lookup_error"] = fba_client.last_error
    return out


@app.on_event("startup")
async def startup_event():
    print("🚀 Defense Halo Customer CVE Analyzer starting...")
    try:
        r.ping()
        print("✅ Redis connected.")
    except Exception as e:
        print(f"⚠️  Redis unavailable: {e}")

    loop = asyncio.get_running_loop()
    await loop.run_in_executor(thread_pool, db.init_db)
    print("✅ SQLite initialised.")
    migrated = await loop.run_in_executor(thread_pool, db.migrate_from_json, CACHE_DIR)
    if migrated:
        print(f"✅ Imported {migrated} tenant JSON cache(s) into SQLite.")

    asyncio.create_task(llm_analysis_worker())
    print("✅ LLM back-fill worker scheduled.")
    asyncio.create_task(notification_scheduler())
    print("✅ Notification scheduler started.")
    asyncio.create_task(daily_scan_scheduler())
    asyncio.create_task(fba_enrichment_worker())
    asyncio.create_task(config_applicability.worker())
    print("✅ Ready.")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5174)
