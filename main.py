import asyncio
import json
import time
import threading
import re
import os
import urllib.parse
import math
from fastapi import FastAPI, Response, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
import httpx
from datetime import datetime, timedelta
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

async def get_llm_analysis(resource_name, model, os_info, cves):
    def call_llm():
        try:
            cve_list = "\n".join([f"- {c['id']}: {c['description']} (Score: {c['score']})" for c in cves])
            prompt = (
                f"Analyze the security risk for resource '{resource_name}' "
                f"(Model: {model}, OS: {os_info}).\n\n"
                f"The following vulnerabilities were found:\n{cve_list}\n\n"
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
    elif resource_type == "vm":
        model = (resource.get("cluster") or {}).get("name") or "Unknown Cluster"
        platform_info = resource.get("platform")
        os_name = platform_info.get("name") if platform_info else None
        os_version = resource.get("custom_fields", {}).get("os_version")
    else:
        return {
            "resource_name": resource_name, "os": "Unknown", "resource_type": "Unknown",
            "resource_category": resource_type, "highest_severity_score": 0.0,
            "cves": [], "is_vulnerable": False, "llm_analysis": "Invalid resource type."
        }

    if not os_name or not os_version:
        print(f"      ⏭️ Skipping {resource_name}: Missing Platform ({os_name}) or OS Version ({os_version})")
        return {
            "resource_name": resource_name, "os": f"{os_name or 'Unknown'} {os_version or ''}",
            "resource_type": model, "resource_category": resource_type,
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

    try:
        device_cves, highest = _parse_cve_response(final_cves_data)

        partial_res = {
            "resource_name": resource_name,
            "os": f"{os_name} {os_version or ''}",
            "resource_type": model,
            "resource_category": resource_type,
            "highest_severity_score": highest,
            "cves": device_cves,
            "is_vulnerable": len(device_cves) > 0,
            "llm_analysis": "Analyzing vulnerabilities..." if device_cves else "No vulnerabilities detected."
        }
        if update_callback:
            await update_callback(partial_res)

        llm_analysis = partial_res["llm_analysis"]
        if device_cves:
            key = f"{resource_name}-{'-'.join(sorted([c['id'] for c in device_cves]))}"
            if key in llm_analysis_cache:
                llm_analysis = llm_analysis_cache[key]
            else:
                llm_analysis = await get_llm_analysis(resource_name, model, f"{os_name} {os_version or ''}", device_cves)
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
            "highest_severity_score": 0.0,
            "cves": [],
            "llm_analysis": f"Error: {str(e)}"
        }
        if update_callback:
            await update_callback(err_res)
        return err_res


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
                            url = data.get("next")
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
                else:
                    model = (d.get("device_type") or {}).get("model") or "Unknown Model"
                    platform_info = d.get("platform")
                    os_name = platform_info.get("name") if platform_info else None
                    os_version = d.get("custom_fields", {}).get("os_build")

                skeleton = {
                    "resource_name": rname,
                    "os": f"{os_name or 'Unknown'} {os_version or ''}",
                    "resource_type": model,
                    "resource_category": rtype,
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
    "status": "idle",      # idle | running | complete | error
    "phase": "",
    "devices_fetched": 0,
    "total_devices": 0,
    "unique_combos": 0,
    "nvd_queried": 0,
    "nvd_cached": 0,
    "nvd_total": 0,
    "tenants_saved": 0,
    "started_at": None,
    "completed_at": None,
    "elapsed_seconds": None,
    "phase_timings": {},
    "error": None,
}
_global_scan_task: asyncio.Task | None = None
_global_sse_subscribers: list[asyncio.Queue] = []


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
        "devices_fetched": 0, "total_devices": 0, "unique_combos": 0,
        "nvd_queried": 0, "nvd_cached": 0, "nvd_total": 0, "tenants_saved": 0,
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
                url = base_url
                page = 1
                while url:
                    try:
                        resp = await client.get(url, headers=headers, timeout=60)
                        resp.raise_for_status()
                        data = resp.json()
                        for d in data.get("results", []):
                            d["_rtype"] = rtype
                        all_devices.extend(data.get("results", []))
                        state["devices_fetched"] = len(all_devices)
                        await _push_global({"type": "progress", "state": dict(state)})
                        url = data.get("next")
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

            # combo_map: nvd_query → {"devices": [...raw netbox dicts...]}
            combo_map: dict[str, list] = {}
            no_platform: list[dict] = []

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
                else:
                    no_platform.append(d)

            state["unique_combos"] = len(combo_map)
            state["phase_timings"]["grouping_seconds"] = round(time.time() - phase_t, 1)
            phase_t = time.time()
            print(f"🔑 Global scan: {len(combo_map)} unique platform/version combos, {len(no_platform)} without platform data")

            # ----------------------------------------------------------------
            # Phase 3 — deduplicated NVD queries via broker
            # ----------------------------------------------------------------
            state["phase"] = f"Querying NVD for {len(combo_map)} unique platform combos"
            state["nvd_total"] = len(combo_map)
            await _push_global({"type": "progress", "state": dict(state)})

            broker = VulnerabilityRequestBroker(cve_cache)
            broker_task = asyncio.create_task(broker.worker(client))
            nvd_results: dict[str, dict] = {}

            async def fetch_one(query: str):
                result = await broker.request_vulnerabilities(query)
                nvd_results[query] = result
                was_cached = query in cve_cache or query in broker.processed_requests
                state["nvd_queried"] += 1
                if was_cached:
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

            def _make_record(d: dict, device_cves: list, highest: float) -> dict:
                rtype = d.get("_rtype", "device")
                pinfo = d.get("platform")
                os_name = pinfo.get("name") if pinfo else None
                if rtype == "vm":
                    model = (d.get("cluster") or {}).get("name") or "Unknown Cluster"
                    os_version = d.get("custom_fields", {}).get("os_version")
                else:
                    model = (d.get("device_type") or {}).get("model") or "Unknown Model"
                    os_version = d.get("custom_fields", {}).get("os_build")
                llm = ("Vulnerabilities found — open this tenant for AI analysis."
                       if device_cves else "No vulnerabilities detected.")
                return {
                    "resource_name": d.get("name") or f"Resource-{d.get('id')}",
                    "os": f"{os_name or 'Unknown'} {os_version or ''}".strip(),
                    "resource_type": model,
                    "resource_category": rtype,
                    "highest_severity_score": highest,
                    "cves": device_cves,
                    "is_vulnerable": len(device_cves) > 0,
                    "llm_analysis": llm,
                }

            for query, devs in combo_map.items():
                cves_data = nvd_results.get(query, {"vulnerabilities": []})
                device_cves, highest = _parse_cve_response(cves_data)
                for d in devs:
                    tenant = d.get("tenant") or {}
                    tid = str(tenant.get("id", ""))
                    tname = tenant.get("name", "Unknown")
                    if not tid:
                        continue
                    tenant_names[tid] = tname
                    tenant_devices.setdefault(tid, []).append(_make_record(d, device_cves, highest))

            for d in no_platform:
                tenant = d.get("tenant") or {}
                tid = str(tenant.get("id", ""))
                tname = tenant.get("name", "Unknown")
                if not tid:
                    continue
                tenant_names[tid] = tname
                tenant_devices.setdefault(tid, []).append(_make_record(d, [], 0.0))

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

            state["phase_timings"]["save_seconds"] = round(time.time() - phase_t, 1)

        elapsed = round(time.time() - t_start, 1)
        state.update({
            "status": "complete",
            "phase": "Complete",
            "elapsed_seconds": elapsed,
            "completed_at": datetime.utcnow().isoformat(),
        })
        print(f"✅ Global scan complete in {elapsed}s — {state['tenants_saved']} tenants, {state['total_devices']} devices, {state['unique_combos']} unique combos")

    except Exception as e:
        elapsed = round(time.time() - t_start, 1)
        state.update({"status": "error", "error": str(e), "elapsed_seconds": elapsed})
        print(f"❌ Global scan failed after {elapsed}s: {e}")
        traceback.print_exc()

    await _push_global({"type": "complete", "state": dict(state)})
    _global_scan_task = None


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


@app.get("/api/leaderboard")
async def get_leaderboard(limit: int = 100, min_devices: int = 1):
    """
    Return tenants ranked by worst security posture (highest CVE score, then most vulnerable devices).
    Useful for prioritising remediation across the estate.
    """
    return db.get_leaderboard(limit=min(limit, 1000), min_devices=min_devices)


# Status endpoint (legacy compat, also used by frontend health check)
@app.get("/status")
async def get_status():
    return {"service": "Defense Halo Customer CVE Analyzer", "status": "ok"}


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
    print("✅ Ready.")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5174)
