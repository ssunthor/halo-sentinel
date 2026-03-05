import asyncio
import json
import time
import threading
import re
import ipaddress
import os
import urllib.parse
import uuid
import socket
from collections import deque, Counter, defaultdict
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Response
from websockets.exceptions import ConnectionClosed
from fastapi.middleware.cors import CORSMiddleware
from confluent_kafka import Consumer, KafkaError
import geoip2.database
import httpx
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor
from pydantic import BaseModel
import redis 
import traceback
from functools import partial
import math
from functools import lru_cache
from feed_cache import get_from_cache, set_in_cache
from config import NETBOX_ROLES
import math
import uvloop
import random

try:
    import orjson
    # orjson natively handles numpy types and usually converts NaN to null
    def json_dumps(x): return orjson.dumps(x).decode('utf-8')
    def json_loads(x): return orjson.loads(x)
except ImportError:
    # Standard JSON fallback needs a custom encoder to handle NaN/Infinity
    class SafeJSONEncoder(json.JSONEncoder):
        def default(self, obj):
            if isinstance(obj, float):
                if math.isnan(obj) or math.isinf(obj):
                    return None
            return super().default(obj)

    def json_dumps(x):
        # Allow NaN=True is default in Python, but we want to catch them or sanitize strings after
        # The easiest clean fix for standard json is string replacement for performance
        try:
            return json.dumps(x, allow_nan=False)
        except ValueError:
            # If NaN detected, do a safe dump (slower but safe) or string replace
            # Quickest hack for standard json library:
            s = json.dumps(x, allow_nan=True) 
            return s.replace(': NaN', ': null').replace(': Infinity', ': null').replace(': -Infinity', ': null')

    def json_loads(x): return json.loads(x)

# --- CONFIGURATION ---
asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())

NETBOX_URL = os.getenv("NETBOX_URL", "http://localhost:8000")
NETBOX_TOKEN = os.getenv("NETBOX_TOKEN", "YOUR_NETBOX_API_TOKEN")

VLLM_ENDPOINT = os.getenv("VLLM_ENDPOINT", "http://10.250.133.8:8080/vllm-gemma3-27b/v1/chat/completions")
VLLM_MODEL = os.getenv("VLLM_MODEL", "google/gemma-3-27b-it")

REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
REDIS_DB = int(os.getenv("REDIS_DB", 0))
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", "password")

KAFKA_CONSUMER = f"morpheus_dashboard_backend_{uuid.uuid4().hex}"

COMMON_KAFKA_CONF = {
    'group.id': KAFKA_CONSUMER,
    'auto.offset.reset': 'latest',
    'max.partition.fetch.bytes': 4 * 1024 * 1024, 
    'fetch.message.max.bytes': 4 * 1024 * 1024, 
    'fetch.wait.max.ms': 500,
    'fetch.min.bytes': 1 * 1024 * 1024, 
    'socket.receive.buffer.bytes': 1024 * 1024,
    'session.timeout.ms': 45000, 
}

KAFKA_CONF_SECURITY = { 
    'bootstrap.servers': os.getenv("KAFKA_SECURITY_SERVERS", "10.250.133.163:29092"), 
    **COMMON_KAFKA_CONF 
}
TOPIC_SECURITY = os.getenv("KAFKA_SECURITY_TOPIC", "morpheus-output")

KAFKA_CONF_NETFLOW = { 
    'bootstrap.servers': os.getenv("KAFKA_NETFLOW_SERVERS", "10.250.133.163:29092"), 
    **COMMON_KAFKA_CONF 
}
TOPIC_NETFLOW = os.getenv("KAFKA_NETFLOW_TOPIC", "netflow-dfp-output")

KAFKA_CONF_NETFLOW_V9 = { 
    'bootstrap.servers': os.getenv("KAFKA_NETFLOW_V9_SERVERS", "10.250.133.29:9092,10.250.133.30:9092,10.250.133.31:9092"), 
    **COMMON_KAFKA_CONF 
}
TOPIC_NETFLOW_V9 = os.getenv("KAFKA_NETFLOW_V9_TOPIC", "netflow_raw")

GEOIP_DB_PATH = "GeoLite2-City.mmdb"
MAP_TTL_SECONDS = 60
TOPOLOGY_TTL_SECONDS = 3600

CACHE_DIR = "/app/cache"
CVE_CACHE_FILE = os.path.join(CACHE_DIR, "cve_cache.json")
HOST_CACHE_FILE = os.path.join(CACHE_DIR, "host_cache.json")
LLM_ANALYSIS_CACHE_FILE = os.path.join(CACHE_DIR, "llm_analysis_cache.json")
OVERALL_SUMMARY_CACHE_FILE = os.path.join(CACHE_DIR, "overall_summary_cache.json")
OVERALL_ANALYSIS_CACHE_FILE = os.path.join(CACHE_DIR, "overall_analysis_cache.json")

vulnerable_devices_cache = {}
overall_summary_cache = ""
overall_analysis_cache = ""
INITIAL_SCAN_COMPLETE = False
if not os.path.exists(CACHE_DIR): os.makedirs(CACHE_DIR, exist_ok=True)

thread_pool = ThreadPoolExecutor(max_workers=16)
dns_pool = ThreadPoolExecutor(max_workers=32)

RE_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
#RE_SUDO = re.compile(r"sudo\[\d+\]:\s+([^:]+)\s+:\s+.*?USER=([^;]+)\s+:\s+COMMAND=(.*)")
RE_SUDO = re.compile(r"sudo(?:\[\d+\])?:\s+([^\s:]+).*?USER=([^\s;]+).*?COMMAND=(.*)", re.IGNORECASE)
RE_TRAFFIC = re.compile(r"SrcIP:\s*([\d\.]+).*?DstIP:\s*([\d\.]+)")
RE_SRC_IP = re.compile(r"SrcIP\s*:\s*([a-fA-F0-9\.\:]+)", re.IGNORECASE)
RE_DST_IP = re.compile(r"DstIP\s*:\s*([a-fA-F0-9\.\:]+)", re.IGNORECASE)

USER_PATTERNS = [
    re.compile(r"New Logon:[\s\S]*?Account Name:\s+([^\s]+)", re.IGNORECASE),
    re.compile(r"Accepted\s+(?:publickey|password|public\s+key)\s+for\s+([\w.-]+)", re.IGNORECASE),
    re.compile(r"for user\s+([\w.-]+)", re.IGNORECASE),
    re.compile(r"(?:user=|User:|Account Name:|user\s+)([\w.-]+)", re.IGNORECASE),
    re.compile(r"sudo:\s+(?!pam_unix)([\w.-]+)", re.IGNORECASE)
]

INVALID_USERS = {
    'slice', 'manager', 'target', 'service', 'daemon', 'process', 'system', 
    'unknown', 'failed', 'error', 'start', 'stop', 'reached', 'listening',
    'dependency', 'socket', 'path', 'timer', 'swap', 'device', 'mount', 'automount',
    'session', 'scope', 'unit', 'job', 'start', 'result', 'done', 'starting', 'stopped',
    'message', 'runtime', 'application', 'with', 'successful', 'input', 'none', 'username',
    'audit', 'login', 'logout', 'authenticated', 'disconnected', 'from', 'user', 'pam_unix',
    'cron', '80', 'acct', 'child', 'msg', 'Background', 
}

try:
    from config import NETBOX_ROLES
except ImportError:
    NETBOX_ROLES = ["Server", "Router", "Switch", "Firewall"]

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

reader = None
if os.path.exists(GEOIP_DB_PATH):
    reader = geoip2.database.Reader(GEOIP_DB_PATH)

GEOIP_ASN_DB_PATH = "GeoLite2-ASN.mmdb"
asn_reader = None
if os.path.exists(GEOIP_ASN_DB_PATH):
    asn_reader = geoip2.database.Reader(GEOIP_ASN_DB_PATH)

GEOIP_COUNTRY_DB_PATH = "GeoLite2-Country.mmdb"
country_reader = None
if os.path.exists(GEOIP_COUNTRY_DB_PATH):
    country_reader = geoip2.database.Reader(GEOIP_COUNTRY_DB_PATH)

def get_asn(ip):
    if not asn_reader or not ip: return None
    try:
        if ipaddress.ip_address(ip).is_private: return None
        response = asn_reader.asn(ip)
        return {
            "asn": response.autonomous_system_number,
            "org": response.autonomous_system_organization
        }
    except: return None

def json_dumps_bytes(x):
    # returns bytes, NOT string.
    # option=orjson.OPT_NON_STR_KEYS handles non-string dictionary keys if necessary
    return orjson.dumps(x, option=orjson.OPT_SERIALIZE_NUMPY)
    
@app.get("/netbox/roles")
async def get_netbox_roles():
    """
    Returns the list of configured Netbox roles.
    """
    return NETBOX_ROLES

@app.get("/cve-proxy")
async def cve_proxy():
    cached_data = get_from_cache("cve_feed")
    if cached_data:
        return Response(content=cached_data, media_type="application/json")

    async with httpx.AsyncClient() as client:
        try:
            end_date = datetime.utcnow()
            start_date = end_date - timedelta(days=7)

            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate={start_date.isoformat()}&pubEndDate={end_date.isoformat()}"

            response = await client.get(url)
            response.raise_for_status()

            set_in_cache("cve_feed", response.content)
            return Response(content=response.content, media_type=response.headers.get('content-type'))
        except httpx.RequestError as exc:
            return Response(content=f"An error occurred while requesting {exc.request.url!r}.", status_code=400)
        except httpx.HTTPStatusError as exc:
            return Response(content=f"Error response {exc.response.status_code} while requesting {exc.request.url!r}.", status_code=exc.response.status_code)

@app.get("/rss-proxy")
async def rss_proxy(url: str):
    cached_data = get_from_cache(url)
    if cached_data:
        return Response(content=cached_data, media_type="application/xml")

    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url)
            response.raise_for_status()

            set_in_cache(url, response.content)
            return Response(content=response.content, media_type=response.headers.get('content-type'))
        except httpx.RequestError as exc:
            return Response(content=f"An error occurred while requesting {exc.request.url!r}.", status_code=400)
        except httpx.HTTPStatusError as exc:
            return Response(content=f"Error response {exc.response.status_code} while requesting {exc.request.url!r}.", status_code=exc.response.status_code)

@lru_cache(maxsize=16384)
def get_site_for_ip(ip_str):
    if not netbox_prefix_cache:
        return None
    
    # 2. String optimization: Don't create ip_address object if it looks like public internet
    # (Adjust based on your internal ranges, e.g., only check 10. or 172. or 192.)
    if not (ip_str.startswith("10.") or ip_str.startswith("172.") or ip_str.startswith("192.")):
        return None

    try:
        ip = ipaddress.ip_address(ip_str)
        if not ip.is_private:
            return None
            
        for net, slug, name in netbox_prefix_cache:
            if ip in net:
                return {"slug": slug, "name": name}
    except:
        return None
    return None

def get_geoip(ip):
    # Mock fallback for POC visualization
    def mock_geo(ip_addr):
        # Deterministic pseudo-random based on IP
        seed = sum(ord(c) for c in ip_addr)
        rnd = random.Random(seed)
        
        locs = [
            ("London", "United Kingdom", "GB", 51.5, -0.12), 
            ("Paris", "France", "FR", 48.85, 2.35), 
            ("Berlin", "Germany", "DE", 52.52, 13.40), 
            ("Tokyo", "Japan", "JP", 35.67, 139.65),
            ("Sydney", "Australia", "AU", -33.86, 151.20), 
            ("Singapore", "Singapore", "SG", 1.35, 103.81),
            ("Frankfurt", "Germany", "DE", 50.11, 8.68), 
            ("Amsterdam", "Netherlands", "NL", 52.36, 4.90),
            ("Madrid", "Spain", "ES", 40.41, -3.70), 
            ("Toronto", "Canada", "CA", 43.65, -79.38)
        ]
        city, country, iso, lat, lon = rnd.choice(locs)

        # Add small jitter so multiple hits to "London" don't stack perfectly
        lat += rnd.uniform(-0.5, 0.5)
        lon += rnd.uniform(-0.5, 0.5)

        return {
            "city": city, "country": country, 
            "iso": iso, "lat": lat, "lon": lon, "ip": ip_addr
        }

    if not ip: return None
    
    try:
        if ipaddress.ip_address(ip).is_private:
             return None
             
        if not reader:
             return mock_geo(ip)

        try:
            response = reader.city(ip)
            city_name = response.city.name
            state_name = response.subdivisions.most_specific.name if response.subdivisions else None
            country_name = response.country.name
            iso_code = response.country.iso_code
            latitude = response.location.latitude
            longitude = response.location.longitude
        except:
            # Fallback to Country DB if City DB fails
            if country_reader:
                try:
                    response = country_reader.country(ip)
                    city_name = None
                    state_name = None
                    country_name = response.country.name
                    iso_code = response.country.iso_code
                    # Country DB doesn't have lat/lon, so we must mock or use country center?
                    # For visualization, we NEED lat/lon. 
                    # If we don't have it, we fallback to mock_geo but keep the real country name?
                    # Let's use mock_geo's logic but force the country name if we have it.
                    
                    # We can't plot it without coords. So we use mock_geo logic but override strings.
                    mock_data = mock_geo(ip)
                    return {
                        "city": country_name, # Use Country as label
                        "real_city": None,
                        "state": None,
                        "country": country_name,
                        "iso": iso_code,
                        "lat": mock_data['lat'], # Use random coord within region (mock_geo logic) or just random
                        "lon": mock_data['lon'],
                        "ip": ip
                    }
                except:
                    return mock_geo(ip)
            else:
                return mock_geo(ip)
        
        # Debug why we might be seeing only Country
        #if not city_name and not state_name:
        #     print(f"DEBUG: {ip} -> Only Country found: {country_name}")
        #elif not city_name:
        #     print(f"DEBUG: {ip} -> City missing, using State: {state_name}")

        # Intelligent Labeling
        location_label = city_name
        if not location_label:
            location_label = state_name
        if not location_label:
            location_label = country_name

        return {
            "city": location_label, # Keeping 'city' key for frontend compatibility as 'primary label'
            "real_city": city_name,
            "state": state_name,
            "country": country_name, 
            "iso": iso_code, 
            "lat": latitude,
            "lon": longitude, 
            "ip": ip
        }
    except: 
        return mock_geo(ip)

def load_cache(file_path):
    if os.path.exists(file_path):
        with open(file_path, "r") as f: return json_loads(f.read())
    return {}

def save_cache(file_path, data):
    with open(file_path, "w") as f: f.write(json_dumps(data))

def clean_float(val):
    try:
        if isinstance(val, (int, float)):
            if math.isnan(val) or math.isinf(val): return 0.0
        return val
    except: return 0.0

# --- BATCH ACCUMULATOR ---
class BatchAccumulator:
    def __init__(self):
        self.logs = []
        self.counts = Counter()
        self.stats_inc = defaultdict(lambda: defaultdict(int))
        self.list_push = defaultdict(list)
        self.topo_nodes = {}
        self.topo_links = defaultdict(lambda: {'val': 0, 'type': 'allow'})
        self.user_activity = defaultdict(lambda: {'count': 0, 'hosts': set(), 'last_host': None})
        self.host_activity = defaultdict(lambda: {'total': 0, 'security': 0, 'score':0.0, 'reason': None, 'sent': 0, 'received': 0})
        self.map_updates = {}
        self.destinations = []
        self.anomaly_entries = [] # For per-host anomaly history
        self.country_activity = Counter()
        self.attack_country_activity = Counter()
        self.threat_stats = defaultdict(float)

    def add_log(self, key, item): self.list_push[key].append(item)
    def add_anomaly_entry(self, host, score, reason, msg):
        self.anomaly_entries.append({
            "host": host, "score": score, "reason": reason, "msg": msg, 
            "time": time.strftime('%Y-%m-%d %H:%M:%S')
        })
    def add_destination(self, item): self.destinations.append(item)
    def add_country_stat(self, country, amount=1): self.country_activity[country] += amount
    def add_attack_country_stat(self, country, amount=1): self.attack_country_activity[country] += amount
    def inc_threat_stat(self, field, amount): self.threat_stats[field] += amount
    def inc_count(self, field, amount=1): self.counts[field] += amount
    def inc_stat(self, key, field, amount=1): self.stats_inc[key][field] += amount

    def update_topo_node(self, nid, updates):
        if nid not in self.topo_nodes:
            self.topo_nodes[nid] = {'val': 0, 'sources': set(), 'score': 0, 'type': 'dst', 'reason': None}
        node = self.topo_nodes[nid]
        for k, v in updates.items():
            if k == 'sources':
                for s in v: node['sources'].add(s)
            elif k == 'val': node['val'] += v
            elif k == 'score': 
                if v > node['score']:
                    node['score'] = v
                    # Only update reason if provided in this specific update
                    if 'reason' in updates:
                        node['reason'] = updates['reason']
            elif k == 'reason':
                if v: node['reason'] = v
            else: node[k] = v

    def update_topo_link(self, src, dst, ltype):
        key = f"{src}-{dst}"
        self.topo_links[key]['val'] += 1
        if ltype == 'block': self.topo_links[key]['type'] = 'block'

    def update_user(self, user, host):
        self.user_activity[user]['count'] += 1
        self.user_activity[user]['last_host'] = host
        self.user_activity[user]['hosts'].add(host)

    def update_host(self, host, is_sec, score=0.0, category=None, reason=None, sent=0, received=0):
        self.host_activity[host]['total'] += 1
        self.host_activity[host]['sent'] += sent
        self.host_activity[host]['received'] += received
        if is_sec: self.host_activity[host]['security'] += 1
        if score > self.host_activity[host]['score']:
            self.host_activity[host]['score'] = score
            if reason:
                self.host_activity[host]['reason'] = reason
        if category:
            self.host_activity[host]['category'] = category

    def update_map(self, ip, data):
        self.map_updates[ip] = data

# --- REDIS STATE STORE ---
class RedisDashboardState:
    def __init__(self):
        print("🔧 INIT: Initializing RedisDashboardState (Byte-Optimized)...")
        connected = False
        while not connected:
            try:
                # Note: decode_responses=True is fine for READS (get_snapshot), 
                # but we will bypass it for WRITES by sending raw bytes.
                self.r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB, password=REDIS_PASSWORD, username="halo_app", decode_responses=True)
                self.r.ping()
                print(f"✅ INIT: Successfully connected to Redis at {REDIS_HOST}:{REDIS_PORT}")
                connected = True
            except redis.ConnectionError as e:
                print(f"❌ INIT: Redis connection failed: {e}")
                time.sleep(2)
        
        self.KEY_LOGS = "morpheus:logs:recent:v2"
        self.KEY_FIREWALL_LOGS = "morpheus:logs:firewall:v2"
        self.KEY_COUNTS = "morpheus:metrics:counts"
        self.KEY_EPS_HISTORY = "morpheus:metrics:eps_history"
        self.KEY_ANOMALY_HISTORY = "morpheus:anomalies:global_history"
        self.KEY_MAJOR_ANOMALIES = "morpheus:anomalies:major_events"
        self.KEY_TOPO_NODES = "morpheus:topology:nodes"
        self.KEY_TOPO_LINKS = "morpheus:topology:links"
        self.KEY_MAP = "morpheus:map:points:v2"
        self.KEY_SUDO_CMDS = "morpheus:sudo:commands"
        self.KEY_USER_REG = "morpheus:users:registry"
        self.KEY_HOST_STATS = "morpheus:hosts:stats"
        self.KEY_NETFLOW_SCATTER = "morpheus:netflow:scatter"
        self.KEY_NETFLOW_CAUSES = "morpheus:netflow:causes"
        self.KEY_COUNTRY_STATS = "morpheus:stats:countries"
        self.KEY_ATTACK_COUNTRY_STATS = "morpheus:stats:attack_countries"
        self.KEY_DESTINATIONS = "morpheus:map:destinations:v2"
        self.KEY_THREAT_ACCUM = "morpheus:metrics:threat:accum"
        self.KEY_THREAT_SCORE = "morpheus:metrics:threat:score"
        self.KEY_HOST_HISTORY_PREFIX = "morpheus:history:host:"
        self.KEY_HOST_ANOMALIES_PREFIX = "morpheus:logs:host:anomalies:"

        self.live_eps = 0.0
        self.eps_components = defaultdict(float)
        self.smoothed_eps = 0.0
        self.current_global_anomaly_sum = 0
        self.current_global_anomaly_count = 0
        
        # Performance Cache
        self.cached_snapshot = None
        self.cached_snapshot_external = None
        self.last_snapshot_time = 0

        if not self.r.exists(self.KEY_COUNTS):
            initial_counts = { "security": 0, "auth_fail": 0, "logons": 0, "sudo": 0, "root": 0, "firewall_block": 0, "netflow_anomalies": 0 }
            self.r.hset(self.KEY_COUNTS, mapping=initial_counts)
        
        # CLEAR ON STARTUP
        self.r.delete(self.KEY_MAJOR_ANOMALIES)

    def refresh_global_snapshot(self):
        """Pre-calculate snapshots for both display modes to save CPU."""
        self.cached_snapshot = self.get_snapshot(show_external=False)
        self.cached_snapshot_external = self.get_snapshot(show_external=True)
        self.last_snapshot_time = time.time()

    def record_host_history(self):
        """
        Periodically captures the current score of all known hosts.
        Target: 24 hours of data with 10-minute intervals (144 points).
        """
        try:
            # Fetch all topology nodes (where live decayed scores live)
            nodes_raw = self.r.hgetall(self.KEY_TOPO_NODES)
            timestamp = time.strftime('%H:%M')
            
            pipe = self.r.pipeline()
            for nid, raw_data in nodes_raw.items():
                node = json_loads(raw_data)
                score = float(node.get('score', 0))
                reason = node.get('reason')
                
                history_key = f"{self.KEY_HOST_HISTORY_PREFIX}{nid}"
                history_point = json_dumps({"time": timestamp, "score": round(score, 2), "reason": reason})
                
                pipe.lpush(history_key, history_point)
                pipe.ltrim(history_key, 0, 143) # Keep 144 points (24 hours at 10m intervals)
            
            pipe.execute()
            print(f"📈 Recorded history for {len(nodes_raw)} hosts")
        except Exception as e:
            print(f"Error recording host history: {e}")

    def get_host_history(self, host_id):
        history_key = f"{self.KEY_HOST_HISTORY_PREFIX}{host_id}"
        raw_history = self.r.lrange(history_key, 0, -1)
        # Reverse because we LUSHed (most recent is at index 0)
        return [json_loads(x) for x in reversed(raw_history)]

    def get_host_anomaly_logs(self, host_id):
        key = f"{self.KEY_HOST_ANOMALIES_PREFIX}{host_id}"
        raw = self.r.lrange(key, 0, -1)
        return [json_loads(x) for x in raw]

    def get_all_hosts(self):
        """
        Returns the list of hosts with active DFP monitoring.
        Used for the Host Inventory tab via REST.
        """
        raw_nodes = self.r.hgetall(self.KEY_TOPO_NODES)
        host_raw = self.r.hgetall(self.KEY_HOST_STATS)
        stats_lookup = {h: json_loads(d) for h, d in host_raw.items()}
        
        dfp_hosts = []
        for nid, raw_data in raw_nodes.items():
            try:
                n = json_loads(raw_data)
                stats = stats_lookup.get(nid, {})
                n['score'] = max(float(n.get('score', 0)), float(stats.get('score', 0)))
                
                # CRITICAL FILTER: Only show hosts with active DFP
                # (Either has an anomaly score OR came from the DFP pipeline)
                sources = n.get('sources', [])
                is_dfp_active = n['score'] > 0 or 'netflow' in sources or 'netflow_v9' in sources
                
                if not is_dfp_active:
                    continue

                n['total_events'] = stats.get('total', 0)
                n['security_events'] = stats.get('security', 0)
                n['sent'] = stats.get('sent', 0)
                n['received'] = stats.get('received', 0)
                n['category'] = stats.get('category')
                n['reason'] = stats.get('reason') or n.get('reason')
                
                # Check for common private ranges or hostnames
                if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", nid):
                    n['is_internal'] = True
                else:
                    n['is_internal'] = (nid.startswith("10.") or nid.startswith("192.168.") or 
                                       (nid.startswith("172.") and 16 <= int(nid.split(".")[1]) <= 31))
                dfp_hosts.append(n)
            except: continue
        
        # Limit to 5000 hosts for UI stability
        return sorted(dfp_hosts, key=lambda x: x.get('score', 0), reverse=True)[:5000]

    def reset_all(self):
        """
        Resets all Redis keys and in-memory counters to clear the dashboard.
        """
        keys_to_delete = [
            self.KEY_LOGS,
            self.KEY_COUNTS,
            self.KEY_EPS_HISTORY,
            self.KEY_ANOMALY_HISTORY,
            self.KEY_MAJOR_ANOMALIES,
            self.KEY_TOPO_NODES,
            self.KEY_TOPO_LINKS,
            self.KEY_MAP,
            self.KEY_SUDO_CMDS,
            self.KEY_USER_REG,
            self.KEY_HOST_STATS,
            self.KEY_NETFLOW_SCATTER,
            self.KEY_NETFLOW_CAUSES,
            self.KEY_COUNTRY_STATS,
            self.KEY_ATTACK_COUNTRY_STATS,
            self.KEY_DESTINATIONS
        ]
        
        # Delete keys
        self.r.delete(*keys_to_delete)
        
        # Re-initialize Counts
        initial_counts = { "security": 0, "auth_fail": 0, "logons": 0, "sudo": 0, "root": 0, "firewall_block": 0, "netflow_anomalies": 0 }
        self.r.hset(self.KEY_COUNTS, mapping=initial_counts)
        
        # Reset memory state
        self.live_eps = 0.0
        self.smoothed_eps = 0.0
        self.current_global_anomaly_sum = 0
        self.current_global_anomaly_count = 0
        
        print("♻️ DASHBOARD STATE RESET")

    def push_log(self, key, item, max_len=100):
        # OPTIMIZATION: Send bytes directly
        self.r.lpush(key, json_dumps_bytes(item))
        self.r.ltrim(key, 0, max_len - 1)

    def update_topology_node(self, node_id, data_update):
        # Fetch existing (requires decode, so we use standard json_loads)
        raw = self.r.hget(self.KEY_TOPO_NODES, node_id)
        if raw: node = json_loads(raw)
        else: node = {'id': node_id, 'name': node_id, 'type': 'dst', 'val': 1, 'sources': [], 'score': 0}
        
        node.update(data_update)
        # OPTIMIZATION: Write bytes back
        self.r.hset(self.KEY_TOPO_NODES, node_id, json_dumps_bytes(node))

    def update_topology_node_direct(self, nid, data_update):
        """Helper for DNS Janitor (single update)"""
        raw = self.r.hget(self.KEY_TOPO_NODES, nid)
        if raw: 
            node = json_loads(raw)
        else: 
            node = {'id': nid, 'name': nid, 'type': 'dst', 'val': 1, 'sources': [], 'score': 0}
        
        node.update(data_update)
        self.r.hset(self.KEY_TOPO_NODES, nid, json_dumps_bytes(node))

    def commit_batch(self, batch: BatchAccumulator):
        pipe = self.r.pipeline()
        current_time = time.time()
        
        # 1. Metric Counts & Stats
        for field, count in batch.counts.items(): 
            pipe.hincrby(self.KEY_COUNTS, field, count)
        for key, fields in batch.stats_inc.items():
            for field, count in fields.items(): 
                pipe.hincrby(key, field, count)
        
        # 2. List Push
        for key, items in batch.list_push.items():
            if items:
                serialized = list(map(json_dumps_bytes, items))
                pipe.lpush(key, *serialized)
                
                # OPTIMIZATION: Keep system logs shorter for faster UI response
                trim_limit = 999 if key == self.KEY_LOGS else 4999
                pipe.ltrim(key, 0, trim_limit)

        # 3. Topology Nodes (Preserve Hostnames logic)
        nodes_to_update = list(batch.topo_nodes.keys())
        if nodes_to_update:
            existing_raw_list = self.r.hmget(self.KEY_TOPO_NODES, nodes_to_update)
            existing_map = {}
            for i, raw_val in enumerate(existing_raw_list):
                if raw_val:
                    try: existing_map[nodes_to_update[i]] = json_loads(raw_val)
                    except: pass

            for nid, data in batch.topo_nodes.items():
                existing = existing_map.get(nid)
                if existing:
                    # Preserve Hostname
                    batch_name = data.get('name')
                    stored_name = existing.get('name')
                    if (not batch_name or batch_name == nid) and stored_name and stored_name != nid:
                        data['name'] = stored_name
                    # Preserve DNS Checked
                    if existing.get('dns_checked'):
                        data['dns_checked'] = True
                    # Preserve Site
                    if 'site' in existing and 'site' not in data:
                        data['site'] = existing['site']
                        data['site_name'] = existing.get('site_name')

                # MERGE SOURCES (Fix for multiple attribution)
                existing_sources = set(existing.get('sources', [])) if existing else set()
                batch_sources = set(data.get('sources', []))
                combined_sources = list(existing_sources | batch_sources)

                node_payload = {
                    'id': str(nid),
                    'name': str(data.get('name', nid)),
                    'type': str(data.get('type', 'dst')),
                    'score': float(data.get('score', 0)),
                    'reason': data.get('reason'),
                    'last_seen': float(current_time),
                    'sources': combined_sources,
                }
                
                # Preserve existing reason if not in this batch
                if not node_payload['reason'] and existing:
                    node_payload['reason'] = existing.get('reason')
                
                if data.get('dns_checked'): node_payload['dns_checked'] = True
                
                # Fast Site Lookup
                if 'site' in data:
                    node_payload['site'] = data['site']
                    node_payload['site_name'] = data.get('site_name')
                elif not existing: # Only lookup if new
                    site_info = get_site_for_ip(nid)
                    if site_info:
                        node_payload['site'] = site_info['slug']
                        node_payload['site_name'] = site_info['name']

                pipe.hset(self.KEY_TOPO_NODES, nid, json_dumps_bytes(node_payload))

        # 4. Links
        for key, data in batch.topo_links.items():
            src, dst = key.split('-')
            payload = { 
                'source': str(src), 'target': str(dst), 
                'value': int(data['val']), 'type': str(data['type']) 
            }
            pipe.hset(self.KEY_TOPO_LINKS, key, json_dumps_bytes(payload))

        # --- FIX START: ACCUMULATE USER ACTIVITY ---
        users_to_update = list(batch.user_activity.keys())
        if users_to_update:
            # A. Fetch existing data for these users to get current totals
            existing_users_raw = self.r.hmget(self.KEY_USER_REG, users_to_update)
            existing_users_map = {}
            for i, raw_val in enumerate(existing_users_raw):
                if raw_val:
                    try: existing_users_map[users_to_update[i]] = json_loads(raw_val)
                    except: pass

            # B. Merge and Update
            for user, data in batch.user_activity.items():
                existing = existing_users_map.get(user, {})
                
                # 1. Add new count to existing count
                current_total = int(existing.get('count', 0))
                new_total = current_total + data['count']
                
                # 2. Merge Hosts List (Keep last 20 unique hosts)
                existing_hosts = set(existing.get('hosts', []))
                new_hosts = data['hosts'] # This is a Set from the batch
                combined_hosts = list(existing_hosts | new_hosts)
                if len(combined_hosts) > 20: 
                    combined_hosts = combined_hosts[-20:]

                payload = { 
                    'user': str(user), 
                    'count': new_total, 
                    'last_host': str(data['last_host']), 
                    'last_seen': float(current_time),
                    'hosts': combined_hosts
                }
                pipe.hset(self.KEY_USER_REG, user, json_dumps_bytes(payload))
        # --- FIX END ---

        # 6. Host Stats (Accumulate)
        hosts_to_update = list(batch.host_activity.keys())
        if hosts_to_update:
            existing_hosts_raw = self.r.hmget(self.KEY_HOST_STATS, hosts_to_update)
            for i, host in enumerate(hosts_to_update):
                raw_val = existing_hosts_raw[i]
                existing = json_loads(raw_val) if raw_val else {'total': 0, 'security': 0, 'score': 0.0}
                
                update_data = batch.host_activity[host]
                
                # Accumulate counts
                new_total = existing.get('total', 0) + update_data['total']
                new_sec = existing.get('security', 0) + update_data.get('security', 0)
                new_sent = existing.get('sent', 0) + update_data.get('sent', 0)
                new_received = existing.get('received', 0) + update_data.get('received', 0)
                
                # Take max score and corresponding reason
                update_score = float(update_data.get('score', 0))
                existing_score = float(existing.get('score', 0))
                
                if update_score > existing_score:
                    new_score = update_score
                    new_reason = update_data.get('reason')
                else:
                    new_score = existing_score
                    new_reason = existing.get('reason')
                
                payload = {
                    'total': new_total, 
                    'security': new_sec, 
                    'score': new_score,
                    'sent': new_sent,
                    'received': new_received
                }
                
                if new_reason:
                    payload['reason'] = new_reason
                
                # Preserve Category
                existing_cat = existing.get('category')
                new_cat = update_data.get('category')
                if new_cat:
                    payload['category'] = new_cat
                elif existing_cat:
                    payload['category'] = existing_cat

                pipe.hset(self.KEY_HOST_STATS, host, json_dumps_bytes(payload))

        for ip, data in batch.map_updates.items():
            data['last_seen'] = current_time
            pipe.hset(self.KEY_MAP, ip, json_dumps_bytes(data))

        # 7. Destinations (List Push)
        if batch.destinations:
            serialized_dests = list(map(json_dumps_bytes, batch.destinations))
            pipe.lpush(self.KEY_DESTINATIONS, *serialized_dests)
            pipe.ltrim(self.KEY_DESTINATIONS, 0, 999) # Keep last 1000

        # 8. Country Stats
        for country, count in batch.country_activity.items():
            pipe.hincrby(self.KEY_COUNTRY_STATS, country, count)

        # 9. Attack Country Stats
        for country, count in batch.attack_country_activity.items():
            pipe.hincrby(self.KEY_ATTACK_COUNTRY_STATS, country, count)

        # 10. Threat Stats Accumulator
        for field, val in batch.threat_stats.items():
            pipe.hincrbyfloat(self.KEY_THREAT_ACCUM, field, val)

        # 11. Per-Host Anomaly Logs
        for entry in batch.anomaly_entries:
            host_key = f"{self.KEY_HOST_ANOMALIES_PREFIX}{entry['host']}"
            pipe.lpush(host_key, json_dumps_bytes(entry))
            pipe.ltrim(host_key, 0, 99) # Keep last 100 entries

        pipe.execute()

    def get_snapshot(self, show_external=False):
        # --- HELPERS ---
        def get_list(key, limit=100):
            raw = self.r.lrange(key, 0, limit - 1)
            return [json_loads(x) for x in raw]

        def get_hash_values(key, limit=None):
            raw = self.r.hgetall(key)
            if limit and len(raw) > limit:
                return [json_loads(v) for i, v in enumerate(raw.values()) if i < limit]
            return [json_loads(v) for v in raw.values()]

        def get_counters(key):
            raw = self.r.hgetall(key)
            data = {k: int(v) for k, v in raw.items()}
            return [{"name": k, "count": v} for k, v in Counter(data).most_common(5)]

        # --- BRIDGE THE GAP: ALIASING LOGIC ---
        
        # 1. Fetch ALL Nodes
        raw_nodes = self.r.hgetall(self.KEY_TOPO_NODES)
        all_nodes_dict = {nid: json_loads(data) for nid, data in raw_nodes.items()}
        
        # 2. Build Alias Map (IP ID -> Hostname ID)
        node_aliases = {}
        new_nodes = {}
        
        for nid, node in all_nodes_dict.items():
            name = node.get('name', nid)
            if nid != name:
                node_aliases[nid] = name
                if name not in all_nodes_dict and name not in new_nodes:
                    new_nodes[name] = {
                        'id': name, 'name': name, 'type': node.get('type', 'dst'),
                        'val': 0, 'score': 0, 'sources': [], 'last_seen': node.get('last_seen', 0)
                    }

        all_nodes_dict.update(new_nodes)

        # 3. Merge Node Scores
        for nid, alias in node_aliases.items():
            if nid in all_nodes_dict and alias in all_nodes_dict:
                source = all_nodes_dict[nid]
                target = all_nodes_dict[alias]
                target['score'] = max(float(target.get('score', 0)), float(source.get('score', 0)))
                target['val'] = target.get('val', 0) + source.get('val', 0)
                src_set = set(target.get('sources', [])) | set(source.get('sources', []))
                target['sources'] = list(src_set)
                target['last_seen'] = max(target.get('last_seen', 0), source.get('last_seen', 0))

        # 4. Fetch and Remap Links
        raw_links = self.r.hgetall(self.KEY_TOPO_LINKS)
        consolidated_links = {} 

        for v in raw_links.values():
            l = json_loads(v)
            src = l['source']
            dst = l['target']
            final_src = node_aliases.get(src, src)
            final_dst = node_aliases.get(dst, dst)

            if final_src == final_dst: continue

            link_key = f"{final_src}-{final_dst}"
            if link_key not in consolidated_links:
                l['source'] = final_src
                l['target'] = final_dst
                consolidated_links[link_key] = l
            else:
                existing = consolidated_links[link_key]
                existing['value'] += l.get('value', 0)
                if l.get('type') == 'block': existing['type'] = 'block'

        all_links = list(consolidated_links.values())
        # We'll filter links AFTER we've decided which nodes to keep
        
        host_raw = self.r.hgetall(self.KEY_HOST_STATS)
        stats_lookup = {h: json_loads(d) for h, d in host_raw.items()}

        def is_internal(ip):
            if not ip: return False
            # Check for common private ranges or hostnames (usually internal)
            if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip): return True
            return (ip.startswith("10.") or ip.startswith("192.168.") or 
                    (ip.startswith("172.") and 16 <= int(ip.split(".")[1]) <= 31))

        # Build prioritized list for GALAXY
        # Priority: 1. Anomalous (Any) > 2. Internal > 3. Regular External
        anomalous_nodes = []
        internal_nodes = []
        regular_external = []

        for nid, n in all_nodes_dict.items():
            if nid in node_aliases: continue
            
            # Merge stats
            stats = stats_lookup.get(nid, {})
            n['score'] = max(float(n.get('score', 0)), float(stats.get('score', 0)))
            n['total_events'] = stats.get('total', 0)
            n['security_events'] = stats.get('security', 0)
            n['sent'] = stats.get('sent', 0)
            n['received'] = stats.get('received', 0)
            n['category'] = stats.get('category')
            n['reason'] = stats.get('reason') or n.get('reason')
            n['is_internal'] = is_internal(nid)

            if n['score'] > 0:
                anomalous_nodes.append(n)
            elif n['is_internal']:
                internal_nodes.append(n)
            else:
                regular_external.append(n)

        # GALAXY LIMITS
        # High Density: 10k nodes / 100k links
        # Low Density: 3k nodes / 15k links
        max_nodes = 10000 if show_external else 3000
        link_limit = 100000 if show_external else 15000
        
        # 1. Start with all anomalous nodes
        final_nodes = anomalous_nodes[:max_nodes]
        
        # 2. Add as many internal nodes as possible
        remaining = max_nodes - len(final_nodes)
        if remaining > 0:
            final_nodes += internal_nodes[:remaining]
        
        # 3. Fill the rest with sampled external noise
        remaining = max_nodes - len(final_nodes)
        if remaining > 0:
            regular_external.sort(key=lambda x: x.get('val', 0), reverse=True)
            final_nodes += regular_external[:remaining]
            
        final_node_ids = {n['id'] for n in final_nodes}
        
        # Now find links connecting these hosts
        relevant_links = [l for l in all_links if l['source'] in final_node_ids and l['target'] in final_node_ids]
        final_links = sorted(relevant_links, key=lambda x: x.get('value', 0), reverse=True)[:link_limit]

        # --- STANDARD METRICS ---
        user_raw = self.r.hgetall(self.KEY_USER_REG)
        users = []
        for u, d in user_raw.items():
            ud = json_loads(d)
            if 'hosts' in ud and isinstance(ud['hosts'], list): ud['hosts'] = ud['hosts'][:10]
            users.append({"user": u, **ud})
        users.sort(key=lambda x: x.get('count', 0), reverse=True)
        users = users[:50]

        host_raw = self.r.hgetall(self.KEY_HOST_STATS)
        all_hosts_data = []
        system_hosts = []
        for h, d in host_raw.items():
            hd = json_loads(d)
            hd['host'] = h
            all_hosts_data.append(hd)
            if hd.get('category') != 'Firewall':
                system_hosts.append(hd)

        all_hosts_data.sort(key=lambda x: x.get('total', 0), reverse=True)
        hosts = all_hosts_data[:20]
        
        # Calculate Top Bandwidth Consumers
        bandwidth_hosts = sorted(all_hosts_data, key=lambda x: (x.get('sent', 0) + x.get('received', 0)), reverse=True)[:10]
        top_bandwidth = [{"host": h['host'], "sent": h.get('sent', 0), "received": h.get('received', 0)} for h in bandwidth_hosts]
        
        # --- FIX START: CALCULATE SUDO STATS ---
        # 1. Fetch recent sudo commands (fetch 500 for better stats, though table only shows 50)
        raw_sudo_list = self.r.lrange(self.KEY_SUDO_CMDS, 0, 499)
        sudo_items = [json_loads(x) for x in raw_sudo_list]
        
        # 2. Aggregate
        sudo_user_counts = Counter(i.get('executing_user') for i in sudo_items if i.get('executing_user'))
        sudo_host_counts = Counter(i.get('host') for i in sudo_items if i.get('host'))
        
        # 3. Format for Frontend
        top_sudo_users = [{"name": k, "value": v} for k, v in sudo_user_counts.most_common(10)]
        top_sudo_hosts = [{"name": k, "value": v} for k, v in sudo_host_counts.most_common(10)]
        # --- FIX END ---

        # --- FIX START: UNIFY ANOMALY HOSTS WITH LIVE DECAYED SCORES ---
        # Instead of using all_hosts_data (peak scores), use final_nodes (decayed scores)
        # to ensure consistency with the Host Inventory and Topology.
        anomaly_hosts = []
        for n in final_nodes:
            # Reformat node to match the expected host object structure
            host_obj = {
                'host': n['id'],
                'score': n.get('score', 0),
                'total': n.get('val', 0),
                'security': stats_lookup.get(n['id'], {}).get('security', 0)
            }
            if n['id'] in stats_lookup:
                host_obj['category'] = stats_lookup[n['id']].get('category')
            
            anomaly_hosts.append(host_obj)
        
        # Sort by live decayed score
        anomaly_hosts.sort(key=lambda x: x.get('score', 0), reverse=True)
        # Filter out firewalls and limit to top 5
        anomaly_hosts = [h for h in anomaly_hosts if h.get('category') != 'Firewall'][:5]
        # --- FIX END ---

        counts = {k: int(v) for k, v in self.r.hgetall(self.KEY_COUNTS).items()}
        nf_raw = self.r.hgetall(self.KEY_NETFLOW_CAUSES)
        nf_causes = [{"name": k, "value": int(v)} for k, v in Counter({k:int(v) for k,v in nf_raw.items()}).most_common(5)]

        threat_raw = self.r.get(self.KEY_THREAT_SCORE)
        threat_data = json_loads(threat_raw) if threat_raw else None

        # Return full host list for inventory (Capped at 3k for stability)
        # Filtered to only show hosts with active DFP
        all_hosts_list = [n for n in (anomalous_nodes + internal_nodes + regular_external) 
                          if n.get('score', 0) > 0 or 'netflow' in n.get('sources', []) or 'netflow_v9' in n.get('sources', [])]
        all_hosts_list = all_hosts_list[:3000]

        return {
            "metrics": { "eps": 0, "counts": counts, "seen_users": len(user_raw), "seen_hosts": len(system_hosts) },
            "charts": { 
                "volume": get_list(self.KEY_EPS_HISTORY, limit=60), 
                "top_hosts": hosts, 
                "top_bandwidth": top_bandwidth,
                "top_countries": get_counters(self.KEY_COUNTRY_STATS),
                "top_attack_countries": get_counters(self.KEY_ATTACK_COUNTRY_STATS)
            },
            "tables": { 
                            "logs": get_list(self.KEY_LOGS, limit=50),
                            "firewall_logs": get_list(self.KEY_FIREWALL_LOGS, limit=100),
                            "users": users,                "sudo_commands": sudo_items[:50], # Reuse the list we fetched above
                "root_shell_sessions": [], 
                "major_anomaly_events": get_list(self.KEY_MAJOR_ANOMALIES, limit=50) 
            },
            "map": get_hash_values(self.KEY_MAP, limit=500), 
            "anomalies": { "global_history": get_list(self.KEY_ANOMALY_HISTORY, limit=60), "top_hosts": anomaly_hosts, "trending_up_hosts": [], "overall_anomaly_score": 0 },
            
            # Updated Sudo Stats
            "sudo_stats": { "top_hosts": top_sudo_hosts, "top_users": top_sudo_users },
            
            "netflow": { "causes": nf_causes, "scatter": get_list(self.KEY_NETFLOW_SCATTER, limit=1000) },
            "topology": { "nodes": final_nodes, "links": final_links },
            "destinations": get_list(self.KEY_DESTINATIONS, limit=200),
            "threat_score": threat_data
        }

    def cleanup_stale_data(self):
        """Prunes old nodes and links to keep the database small and fast."""
        now = time.time()
        # Run every 60 seconds
        if now % 60 > 5: return

        node_cutoff = now - 3600  # 1 Hour for nodes
        link_cutoff = now - 600   # 10 Minutes for links (keep galaxy fresh)
        
        try:
            # 1. Prune Nodes
            stale_nodes = []
            for nid, raw_data in self.r.hscan_iter(self.KEY_TOPO_NODES, count=1000):
                try:
                    node = json_loads(raw_data)
                    if node.get('last_seen', 0) < node_cutoff:
                        stale_nodes.append(nid)
                except: pass
            
            if stale_nodes:
                print(f"🧹 Janitor: Pruning {len(stale_nodes)} old nodes...")
                for i in range(0, len(stale_nodes), 1000):
                    self.r.hdel(self.KEY_TOPO_NODES, *stale_nodes[i:i+1000])

            # 2. Prune Links (Netflow creates MILLIONS of these)
            # Since links don't have 'last_seen' in the current schema, 
            # we will look them up in batches or just wipe them if they exceed a count.
            # Faster approach: If links > 20k, just clear them to reset the galaxy.
            link_count = self.r.hlen(self.KEY_TOPO_LINKS)
            if link_count > 20000:
                print(f"🧹 Janitor: Galaxy Overload ({link_count} links). Clearing links to reset...")
                self.r.delete(self.KEY_TOPO_LINKS)

        except Exception as e:
            print(f"Janitor Error: {e}")
    
    def update_topology_node_direct(self, nid, data_update):
        """Helper for DNS Janitor (single update) to write directly to Redis"""
        # Fetch current state to preserve existing fields
        raw = self.r.hget(self.KEY_TOPO_NODES, nid)
        if raw: 
            node = json_loads(raw)
        else: 
            node = {'id': nid, 'name': nid, 'type': 'dst', 'val': 1, 'sources': [], 'score': 0}
        
        # Apply updates (e.g., setting 'name' to hostname)
        node.update(data_update)
        
        # Write back to Redis immediately
        self.r.hset(self.KEY_TOPO_NODES, nid, json_dumps(node))

    def perform_passive_decay(self):
        """
        Background task to slowly heal nodes that are not receiving 
        new traffic but still have high anomaly scores.
        """
        try:
            # Fetch all nodes currently in the topology
            raw_nodes = self.r.hgetall(self.KEY_TOPO_NODES)
            pipe = self.r.pipeline()
            updates_queued = False

            for nid, raw_data in raw_nodes.items():
                try:
                    node = json_loads(raw_data)
                    current_score = float(node.get('score', 0))

                    # Only process nodes that actually need healing
                    if current_score > 0:
                        # Decay by 10% every second (adjust 0.90 to change speed)
                        new_score = current_score * 0.90
                        
                        # Snap to 0 if it gets insignificant
                        if new_score < 0.1: 
                            new_score = 0.0

                        if new_score != current_score:
                            node['score'] = new_score
                            # Write back the decayed score
                            pipe.hset(self.KEY_TOPO_NODES, nid, json_dumps(node))
                            updates_queued = True
                except:
                    continue

            if updates_queued:
                pipe.execute()
                
        except Exception as e:
            print(f"Decay Error: {e}")

state = RedisDashboardState()

# --- PURE FUNCTION: PARSE LOG (HARDENED) ---
# --- OPTIMIZED PARSER ---
def parse_log_entry(raw_bytes):
    updates = {
        'log': None, 'counts': Counter(), 'stat_inc': defaultdict(int),
        'topo_node': {}, 'topo_link': {}, 'user': None, 'host': None,
        'map': None, 'scatter': None, 'major_anomaly': None, 'sudo': None,
        'global_anomaly_score': 0.0
    }

    try:
        # FAST PATH: Parse bytes directly (supported by standard json and orjson)
        payload = json_loads(raw_bytes)
    except:
        return updates

    # Pre-compute common fields to avoid repeated lookups
    timestamp_str = time.strftime('%H:%M:%S')
    raw_msg = payload.get("message") or ""

    # 1. NETFLOW PATH (Fastest - No Regex)
    if "feature_octets" in payload:
        cause = payload.get("anomaly_cause") or "Unknown"
        rec_err = clean_float(payload.get("mean_abs_err", 0))
        octets = payload.get("feature_octets", 0)
        user_id = payload.get("user_id") or "unknown"
        
        real_dport = 0
        # Simple string check before regex
        if '(' in raw_msg:
            # simple split is faster than regex for fixed formats
            try: real_dport = int(raw_msg.split('Port (')[1].split(')')[0])
            except: pass
        
        if real_dport > 65535: real_dport = 0
        clean_host = user_id.split('/')[0] if user_id else "unknown"

        clean_score = 5.0 + math.log10(rec_err) if rec_err > 100 else rec_err
        clean_score = min(clean_float(clean_score) or 0.0, 10.0)

        updates['scatter'] = {
            "bytes": round(octets, 2), "port": real_dport, "y": round(clean_score, 4), 
            "cause": cause, "host": clean_host, "time": timestamp_str
        }
        updates['stat_inc'][state.KEY_NETFLOW_CAUSES] = {str(cause): 1}
        if rec_err > 1.0: updates['counts']['netflow_anomalies'] += 1
        
        # Add to topology map immediately
        updates['topo_node'][clean_host] = {'type': 'src', 'sources': {'netflow'}, 'score': clean_score, 'val': 1}
        updates['host'] = (clean_host, True, clean_score)

        msg_str = f"Netflow: {cause} (Err: {rec_err:.1f})"
        updates['log'] = {
            "time": timestamp_str, "host": user_id, "msg": msg_str,
            "category": "Netflow DFP", "priority": "high" if clean_score > 8 else "medium",
            "is_security_event": True, "anomaly_score": clean_score,
            "uuid": str(uuid.uuid4())
        }
        return updates

    # 2. SYSLOG PATH (Optimized)
    main_label = payload.get("main_label") or "N/A"
    hostname = payload.get("source") or "unknown"
    lower_msg = raw_msg.lower()
    main_label_upper = main_label.upper()
    
    # CATEGORY DETERMINATION (Robust Substring Matching)
    if any(k in lower_msg for k in ["ftd", "fpfw", "asa", "deny", "block", "firewall"]):
        category = "Firewall"
        is_sec = True
    elif "squid-" in lower_msg:
        category = "Proxy"
        is_sec = False
    elif "postgres" in lower_msg or "mysql" in lower_msg:
        category = "Database"
        is_sec = False
    elif "httpd" in lower_msg or "haproxy" in lower_msg:
        category = "HTTP"
        is_sec = False
    elif "AUTHENTICATION" in main_label_upper or "LOGIN" in main_label_upper or "authentication" in lower_msg or "logoff" in lower_msg or "radiusd" in lower_msg:
        category = "Authentication"
        is_sec = True
    elif "AUTHORIZATION" in main_label_upper or "authorization" in lower_msg:
        category = "Authorization"
        is_sec = True
    elif "INTRUSION" in main_label_upper or "THREAT" in main_label_upper:
        category = "Firewall"
        is_sec = True
    elif "SYSTEM" in main_label_upper or "KERNEL" in main_label_upper or "NON_SECURITY" in main_label_upper or "system daemon" in lower_msg:
        category = "System"
        is_sec = False
    elif "SECURITY" in main_label_upper or "ssh" in lower_msg:
        category = "Security"
        is_sec = True
    else:
        category = "Other"
        is_sec = False

    # OPTIMIZATION: Only run User Regex if keywords exist
    user = "N/A"
    if "user" in lower_msg or "login" in lower_msg or "root" in lower_msg:
        for pattern in USER_PATTERNS:
            m = pattern.search(raw_msg)
            if m: 
                user = m.group(1).rstrip('.').strip()
                break

    # Update Counts
    if "FAILURE" in main_label.upper(): updates['counts']['auth_fail'] += 1
    elif "SUCCESS" in main_label.upper(): updates['counts']['logons'] += 1
    
    if 'sudo' in lower_msg:
        updates['counts']['sudo'] += 1
        # OPTIMIZATION: Only run Sudo Regex if "COMMAND=" is present
        if "COMMAND=" in raw_msg:
            sudo_match = RE_SUDO.search(raw_msg)
            if sudo_match:
                updates['sudo'] = {
                    "host": hostname, "executing_user": sudo_match.group(1).strip(), 
                    "run_as_user": sudo_match.group(2).strip(), 
                    "command": sudo_match.group(3).strip(), "time": timestamp_str
                }

    if is_sec: updates['counts']['security'] += 1
    if user != "N/A": updates['user'] = (user, hostname)

    # REMOVED: expensive RE_IP.findall scan. It's too slow for high throughput.
    
    # Check Anomaly Score
    sys_anomaly_score = min(clean_float(payload.get("anomaly_score", -1)) or 0.0, 10.0)
    if sys_anomaly_score <= 0:
        prio = (payload.get("priority_str") or "low").lower()
        if prio == "critical": sys_anomaly_score = 10.0
        elif prio == "high": sys_anomaly_score = 6.0
        elif is_sec: sys_anomaly_score = 3.0

    if sys_anomaly_score > 0:
        updates['topo_node'][hostname] = {'type': 'src', 'sources': {'syslog'}, 'score': sys_anomaly_score, 'val': 1}
        updates['global_anomaly_score'] = sys_anomaly_score
        if sys_anomaly_score >= 5: 
             updates['major_anomaly'] = {
                "host": hostname, "current_score": round(sys_anomaly_score, 2),
                "reason": payload.get("anomaly_cause") or "Critical System Event", "time": timestamp_str
            }
    updates['host'] = (hostname, is_sec, sys_anomaly_score)

    # OPTIMIZATION: Faster Link Extraction (String search before Regex)
    if "SrcIP" in raw_msg and "DstIP" in raw_msg:
        try:
            # Split logic is much faster than Regex engine
            # Adjust the delimiters (': ' or '=') based on your actual log format
            part1 = raw_msg.split('SrcIP: ', 1)[1]
            src = part1.split(' ', 1)[0].strip()

            part2 = raw_msg.split('DstIP: ', 1)[1]
            dst = part2.split(' ', 1)[0].strip()

            # Logic continues...
            ltype = "block" if ("block" in lower_msg or "deny" in lower_msg) else "allow"
            key = f"{src}-{dst}"
            batch.topo_links[key]['val'] += 1
            if ltype == 'block': batch.topo_links[key]['type'] = 'block'

            batch.update_topo_node(src, {'type': 'src', 'sources': {'syslog'}, 'val': 1})
            batch.update_topo_node(dst, {'type': 'dst', 'sources': {'syslog'}, 'val': 1})
        except IndexError:
            pass

    priority = (payload.get("priority_str") or "low").lower()
    if sys_anomaly_score > 3: priority = "high"



    updates['log'] = {
        "time": timestamp_str, "host": hostname, "msg": raw_msg, 
        "category": "Security" if is_sec else "Other", 
        "priority": priority, "uuid": str(uuid.uuid4()),
        "is_security_event": is_sec, "anomaly_score": sys_anomaly_score,
        "mean_abs_err": clean_float(payload.get("mean_abs_err", -1)),
        "anomaly_cause": payload.get("anomaly_cause")
    }
    return updates

class DeduplicationFilter:
    def __init__(self, ttl_seconds=2.0):
        self.cache = {}
        self.lock = threading.Lock()
        self.ttl = ttl_seconds
        self.last_cleanup = time.time()

    def is_duplicate(self, key):
        with self.lock:
            now = time.time()
            if now - self.last_cleanup > 10:
                self.cache = {k: v for k, v in self.cache.items() if now - v < self.ttl}
                self.last_cleanup = now
            
            if key in self.cache:
                return True
            self.cache[key] = now
            return False

deduplicator = DeduplicationFilter(ttl_seconds=2.0)
anomaly_deduplicator = DeduplicationFilter(ttl_seconds=60.0)

# --- NUCLEAR OPTION: DIRECT INJECTION PARSER ---
def process_log_into_batch(raw_bytes, batch):
    try:
        # FAST PATH: Decode
        payload = json_loads(raw_bytes)
    except:
        return

    # PRE-COMPUTE (Avoid repeated lookups)
    timestamp_str = time.strftime('%H:%M:%S')
    
    # Try to use provided timestamp if available
    if payload.get("time_received_ns"):
        try:
            ts_ns = float(payload.get("time_received_ns"))
            timestamp_str = datetime.fromtimestamp(ts_ns / 1e9).strftime('%H:%M:%S')
        except: pass
    elif payload.get("timestamp"):
        try:
            # Handle both ISO strings and epoch numbers
            ts = payload.get("timestamp")
            if isinstance(ts, (int, float)):
                timestamp_str = datetime.fromtimestamp(ts).strftime('%H:%M:%S')
            else:
                timestamp_str = ts.split('T')[-1].split('.')[0] # Quick extraction
        except: pass

    raw_msg = payload.get("message") or ""

    # FILTER: Exclude ns1.gtt.net
    if payload.get("source") == "ns1.gtt.net":
        return

    # DEDUPLICATION (Skip for Firewalls)
    is_firewall = "ftd" in raw_msg.lower() or "fpfw" in raw_msg.lower() or "%ftd" in raw_msg.lower()
    dedupe_source = payload.get("source") or payload.get("user_id") or payload.get("src_ip") or payload.get("src_addr") or "unknown"
    dedupe_key = hash(f"{dedupe_source}:{raw_msg}")
    
    if not is_firewall and deduplicator.is_duplicate(dedupe_key):
        return

    if "security: info: client" in raw_msg or "query-errors: info: client" in raw_msg:
        return

    # 1. NETFLOW DFP PATH (Morpheus Output)
    # Check for anomaly_score and any of the common host identification fields
    if "anomaly_score" in payload and any(k in payload for k in ["src_ip", "src_addr", "user_id"]):
        score = min(clean_float(payload.get("anomaly_score", 0)) or 0.0, 10.0)
        rec_err = clean_float(payload.get("mean_abs_err", 0)) or 0.0
        
        # Determine Cause (Adjusted for Morpheus DFP: 0.0 is Learning, >0 is Normal/Anomalous)
        cause = payload.get("anomaly_cause")
        if not cause:
            if score == 0.0: cause = "Learning..."
            elif score <= 2.0: cause = "Normal"
            else: cause = "Anomalous Activity"
        
        # Robust IP Extraction: Fallback through possible fields
        host_id = payload.get("src_ip") or payload.get("src_addr") or payload.get("user_id") or "unknown"
        clean_host = str(host_id).split('/')[0] if '/' in str(host_id) else str(host_id)
        
        # Destination info
        dst_ip = payload.get("dst_ip") or payload.get("dst_addr") or "unknown"
        
        # Traffic info
        try:
            real_dport = int(payload.get("dst_port") or 0)
            real_sport = int(payload.get("src_port") or 0)
        except (ValueError, TypeError):
            real_dport = 0
            real_sport = 0

        # Protocol Handling (Supports "TCP", "UDP", or 6, 17)
        proto_raw = payload.get("protocol") or payload.get("proto") or 0
        if isinstance(proto_raw, str):
            p_up = proto_raw.upper()
            if p_up == "TCP": proto = 6
            elif p_up == "UDP": proto = 17
            elif p_up == "ICMP": proto = 1
            else:
                try: proto = int(proto_raw)
                except: proto = 0
        else:
            try: proto = int(proto_raw or 0)
            except: proto = 0
            
        bytes_val = payload.get("bytes") or payload.get("log_bytes") or 0
        if "log_bytes" in payload and payload["log_bytes"] is not None:
            try:
                # Reverse log scale if needed, but here we just want a display value
                bytes_val = math.exp(float(payload["log_bytes"])) - 1
            except: bytes_val = 0
        else:
            try: bytes_val = float(bytes_val or 0)
            except: bytes_val = 0
            
        # --- REASON ENRICHMENT ---
        if score > 2.0 and "volume" in str(cause).lower():
            cause = f"Traffic Volume Spike (Port {real_dport})"
        elif score > 5.0 and ("Unknown" in str(cause) or "Normal" in str(cause) or "Learning" in str(cause)):
            cause = f"Anomalous Connection Pattern ({real_dport})"

        # DIRECT BATCH UPDATE
        batch.add_log(state.KEY_NETFLOW_SCATTER, {
            "bytes": round(bytes_val, 2), "port": real_dport, "y": round(score, 4), 
            "cause": str(cause), "host": clean_host, "time": timestamp_str
        })
        batch.inc_stat(state.KEY_NETFLOW_CAUSES, str(cause), 1)
        if rec_err > 1.0: batch.counts['netflow_anomalies'] += 1
        
        # TOPOLOGY (Nodes and Links)
        batch.update_topo_node(clean_host, {'type': 'src', 'sources': {'netflow'}, 'score': score, 'val': 1, 'reason': str(cause)})
        if dst_ip != "unknown":
            batch.update_topo_node(dst_ip, {'type': 'dst', 'sources': {'netflow'}, 'val': 1})
            batch.update_topo_link(clean_host, dst_ip, 'allow')

        # HOST STATS
        batch.update_host(clean_host, True, score, "Netflow DFP", reason=str(cause), sent=bytes_val)
        if dst_ip != "unknown":
            batch.update_host(dst_ip, False, 0.0, "Network Node", received=bytes_val)

        # PORT TRACKING
        if real_dport > 0:
            proto_name = "TCP" if proto == 6 else "UDP" if proto == 17 else str(proto)
            port_label = f"{real_dport}/{proto_name}"
            batch.inc_stat(f"morpheus:host:{clean_host}:ports", port_label, 1)
            if dst_ip != "unknown":
                batch.inc_stat(f"morpheus:host:{dst_ip}:ports", port_label, 1)

        # Log Anomaly Spike (Deduplicated per 60s)
        if score > 2.0:
            anomaly_key = hash(f"anomaly:{clean_host}:{cause}")
            if not anomaly_deduplicator.is_duplicate(anomaly_key):
                batch.add_anomaly_entry(clean_host, score, str(cause), f"Port: {real_dport}, Bytes: {bytes_val:.0f}")

        # --- THREAT STATS (Network) ---
        batch.inc_threat_stat('net_sum', score)
        batch.inc_threat_stat('net_count', 1.0)

        # --- DESTINATION EXTRACTION ---
        enriched_data = {}
        if dst_ip != "unknown":
             dst_geo = get_geoip(dst_ip)
             if dst_geo:
                dst_geo['time'] = timestamp_str
                dst_geo['src_ip'] = clean_host
                dst_geo['src_port'] = real_sport
                dst_geo['dst_port'] = real_dport

                asn_info = get_asn(dst_ip)
                if asn_info:
                    dst_geo.update(asn_info)

                batch.add_destination(dst_geo)
                if dst_geo.get('country'):
                    batch.add_country_stat(dst_geo['country'])
                enriched_data = dst_geo

        # LOG ENTRY
        fast_uuid = f"{time.time()}-{clean_host}-{random.randint(0, 1000000)}"
        log_payload = {
            "time": timestamp_str, "host": clean_host, "msg": f"Netflow DFP: {cause} (Score: {score:.2f})",
            "category": "Netflow DFP", "priority": "high" if score > 8 else "medium",
            "is_security_event": True, "anomaly_score": score,
            "uuid": fast_uuid
        }
        log_payload.update(enriched_data)
        batch.add_log(state.KEY_LOGS, log_payload)
        return

    # 2. LEGACY NETFLOW PATH (If still receiving feature_octets format)
    if "feature_octets" in payload:
        cause = payload.get("anomaly_cause") or "Unknown"
        # Inline Float Cleaning
        rec_err = payload.get("mean_abs_err", 0)
        if isinstance(rec_err, (int, float)):
             if math.isnan(rec_err) or math.isinf(rec_err): rec_err = 0.0
        else: rec_err = 0.0
            
        octets = payload.get("feature_octets", 0)
        user_id = payload.get("user_id") or "unknown"
        
        # Fast String Split instead of Regex
        real_dport = 0
        if '(' in raw_msg:
            try: real_dport = int(raw_msg.split('Port (')[1].split(')')[0])
            except: pass
        
        clean_host = user_id.split('/')[0] if user_id else "unknown"
        
        # Inline Score Calc
        clean_score = 5.0 + math.log10(rec_err) if rec_err > 100 else rec_err
        if math.isnan(clean_score) or math.isinf(clean_score): clean_score = 0.0
        clean_score = min(clean_score, 10.0)

        # --- REASON ENRICHMENT (Netflow) ---
        if clean_score > 2.0 and "volume" in cause.lower():
            cause = f"Traffic Volume Spike (Port {real_dport})"
        elif clean_score > 5.0 and "Unknown" in cause:
            cause = f"Anomalous Connection Pattern ({real_dport})"

        # DIRECT BATCH UPDATE (No intermediate dicts)
        batch.add_log(state.KEY_NETFLOW_SCATTER, {
            "bytes": round(octets, 2), "port": real_dport, "y": round(clean_score, 4), 
            "cause": cause, "host": clean_host, "time": timestamp_str
        })
        batch.inc_stat(state.KEY_NETFLOW_CAUSES, str(cause), 1)
        if rec_err > 1.0: batch.counts['netflow_anomalies'] += 1
        
        batch.update_topo_node(clean_host, {'type': 'src', 'sources': {'netflow'}, 'score': clean_score, 'val': 1, 'reason': cause})
        batch.update_host(clean_host, True, clean_score, "Netflow DFP", reason=cause)

        # --- THREAT STATS (Network) ---
        batch.inc_threat_stat('net_sum', clean_score)
        batch.inc_threat_stat('net_count', 1.0)

        # --- NEW: NETFLOW DESTINATION EXTRACTION (Optimized) ---
        enriched_data = {}
        try:
            if ',' in raw_msg and raw_msg.count(',') > 10:
                parts = raw_msg.split(',')
                dst_raw = parts[9] # "1.2.3.4/24"
                dst_ip = dst_raw.split('/')[0]
                
                if dst_ip.count('.') == 3:
                     dst_geo = get_geoip(dst_ip)
                     if dst_geo:
                        dst_geo['time'] = timestamp_str
                        dst_geo['src_ip'] = parts[6].split('/')[0]
                        dst_geo['src_port'] = parts[7]
                        dst_geo['dst_port'] = parts[10]

                        asn_info = get_asn(dst_ip)
                        if asn_info:
                            dst_geo.update(asn_info)

                        batch.add_destination(dst_geo)
                        if dst_geo.get('country'):
                            batch.add_country_stat(dst_geo['country'])
                        enriched_data = dst_geo
        except: pass
        # -------------------------------------------

        # FAST UUID: Time + Random Int is 100x faster than uuid.uuid4()
        fast_uuid = f"{time.time()}-{math.floor(octets)}-{random.randint(0, 1000000)}"
        
        log_payload = {
            "time": timestamp_str, "host": user_id, "msg": f"Netflow: {cause}",
            "category": "Netflow DFP", "priority": "high" if clean_score > 8 else "medium",
            "is_security_event": True, "anomaly_score": clean_score,
            "uuid": fast_uuid
        }
        log_payload.update(enriched_data)
        batch.add_log(state.KEY_LOGS, log_payload)
        return

    # 2. SYSLOG
    main_label = payload.get("main_label") or "N/A"
    hostname = payload.get("source") or "unknown"
    lower_msg = raw_msg.lower()
    enriched_data = {}
    
    is_sec = "SECURITY" in main_label and "NON_SECURITY" not in main_label
    if not is_sec:
        if "denied" in lower_msg or "block" in lower_msg: is_sec = True
        elif "fail" in lower_msg or "invalid" in lower_msg: is_sec = True

    # CATEGORY DETERMINATION (Robust Substring Matching)
    main_label_upper = main_label.upper()
    
    if any(k in lower_msg for k in ["ftd", "fpfw", "asa", "deny", "block", "firewall"]):
        category = "Firewall"
        is_sec = True
    elif "AUTHENTICATION" in main_label_upper or "LOGIN" in main_label_upper or "authentication" in lower_msg:
        category = "Authentication"
        is_sec = True
    elif "AUTHORIZATION" in main_label_upper or "authorization" in lower_msg:
        category = "Authorization"
        is_sec = True
    elif "INTRUSION" in main_label_upper or "THREAT" in main_label_upper:
        category = "Firewall"
        is_sec = True
    elif "SYSTEM" in main_label_upper or "KERNEL" in main_label_upper or "NON_SECURITY" in main_label_upper:
        category = "System"
        is_sec = False
    elif "SECURITY" in main_label_upper:
        category = "Security"
        is_sec = True
    else:
        category = "Other"
        is_sec = False

    # COUNTS
    if "FAILURE" in main_label.upper(): 
        batch.counts['auth_fail'] += 1
        batch.inc_threat_stat('auth_fail', 1.0)
    elif "SUCCESS" in main_label.upper(): batch.counts['logons'] += 1
    
    if category == "Firewall":
        batch.counts['firewall_block'] += 1
    elif is_sec:
        batch.counts['security'] += 1

    # SUDO EXTRACTION
    if 'sudo' in lower_msg:
        batch.counts['sudo'] += 1
        if "command=" in lower_msg:
            sudo_match = RE_SUDO.search(raw_msg)
            if sudo_match:
                batch.add_log(state.KEY_SUDO_CMDS, {
                    "host": hostname, 
                    "executing_user": sudo_match.group(1).strip(), 
                    "run_as_user": sudo_match.group(2).strip(), 
                    "command": sudo_match.group(3).strip(), 
                    "time": timestamp_str
                })

    # USER EXTRACTION (Only if needed)
    if "user" in lower_msg or "login" in lower_msg:
        for pattern in USER_PATTERNS:
            m = pattern.search(raw_msg)
            if m: 
                raw_user = m.group(1).rstrip('.').strip()
                
                # --- FILTER CHECK ---
                if (len(raw_user) > 1 and 
                    raw_user.lower() not in INVALID_USERS and 
                    re.match(r"^[a-zA-Z0-9_\-\.]+$", raw_user)):
                    
                    batch.update_user(raw_user, hostname)
                break

    # ANOMALY SCORE
    sys_anomaly_score = payload.get("anomaly_score", -1)
    if isinstance(sys_anomaly_score, (int, float)):
         if math.isnan(sys_anomaly_score) or math.isinf(sys_anomaly_score): sys_anomaly_score = 0.0
         else: sys_anomaly_score = min(float(sys_anomaly_score), 10.0)
    else: sys_anomaly_score = 0.0

    if sys_anomaly_score <= 0:
        prio = (payload.get("priority_str") or "low").lower()
        if prio == "critical": sys_anomaly_score = 10.0
        elif prio == "high": sys_anomaly_score = 6.0
        elif is_sec: sys_anomaly_score = 3.0

    # --- REASON ENRICHMENT (Syslog) ---
    anomaly_cause = payload.get("anomaly_cause") or ""
    if sys_anomaly_score > 3.0:
        if category == "Authentication" and "FAILURE" in main_label.upper():
            anomaly_cause = "Elevated Authentication Failures"
        elif category == "Firewall":
            anomaly_cause = "High-Volume Firewall Blocks"
        elif category == "Authorization":
            anomaly_cause = "Unauthorized Access Attempts"
        elif "sudo" in lower_msg:
            anomaly_cause = "Anomalous Sudo Activity"
        elif not anomaly_cause:
            anomaly_cause = "Significant System DNA Divergence"

    # IGNORE FIREWALLS FOR DFP/ANOMALY STATS
    if category == "Firewall":
        sys_anomaly_score = 0.0

    # TOPOLOGY NODES
    if category != "Firewall":
        if sys_anomaly_score > 0:
            batch.update_topo_node(hostname, {'type': 'src', 'sources': {'syslog'}, 'score': sys_anomaly_score, 'val': 1, 'reason': anomaly_cause})
            state.current_global_anomaly_sum += sys_anomaly_score
            state.current_global_anomaly_count += 1
            
            # Threat Stats (System)
            batch.inc_threat_stat('sys_sum', sys_anomaly_score)
            batch.inc_threat_stat('sys_count', 1.0)

            # Log Anomaly Spike (Deduplicated per 60s)
            if sys_anomaly_score > 3.0:
                anomaly_key = hash(f"anomaly:{hostname}:{anomaly_cause}")
                if not anomaly_deduplicator.is_duplicate(anomaly_key):
                    batch.add_anomaly_entry(hostname, sys_anomaly_score, anomaly_cause, raw_msg[:200])
        else:
            batch.update_topo_node(hostname, {'type': 'src', 'sources': {'syslog'}, 'val': 1})
        
    batch.update_host(hostname, is_sec, sys_anomaly_score, category, reason=anomaly_cause)

    # FAST LINK EXTRACTION
    if "SrcIP" in raw_msg and "DstIP" in raw_msg:
        src_match = RE_SRC_IP.search(raw_msg)
        dst_match = RE_DST_IP.search(raw_msg)
        if src_match and dst_match:
            src = src_match.group(1)
            dst = dst_match.group(1)
            ltype = "block" if ("block" in lower_msg or "deny" in lower_msg) else "allow"
            
            key = f"{src}-{dst}"
            batch.topo_links[key]['val'] += 1
            if ltype == 'block': 
                batch.topo_links[key]['type'] = 'block'
                
                # --- ATTACK COUNTRY TRACKING ---
                # Sample GeoIP lookups to avoid massive overhead
                if random.random() < 0.1: # Sample 10%
                    src_geo = get_geoip(src)
                    if src_geo:
                        if src_geo.get('country'):
                            batch.add_attack_country_stat(src_geo['country'])
                        src_geo['action'] = 'block'
                        batch.update_map(src, src_geo)
            else:
                if random.random() < 0.01: # Sample 1% for ALLOW traffic
                    src_geo = get_geoip(src)
                    if src_geo:
                        src_geo['action'] = 'allow'
                        batch.update_map(src, src_geo)
            
            batch.update_topo_node(src, {'type': 'src', 'sources': {'syslog'}, 'val': 1})
            batch.update_topo_node(dst, {'type': 'dst', 'sources': {'syslog'}, 'val': 1})

            # --- DESTINATION ENRICHMENT (Sampled) ---
            if random.random() < 0.05: # Sample 5%
                dst_geo = get_geoip(dst)
                if dst_geo:
                    dst_geo['time'] = timestamp_str
                    dst_geo['src_ip'] = src
                    
                    try:
                        sp_match = re.search(r"SrcPort\s*:\s*(\d+)", raw_msg, re.I)
                        dp_match = re.search(r"DstPort\s*:\s*(\d+)", raw_msg, re.I)
                        dst_geo['src_port'] = sp_match.group(1) if sp_match else "0"
                        dst_geo['dst_port'] = dp_match.group(1) if dp_match else "0"
                    except:
                        dst_geo['src_port'] = "0"
                        dst_geo['dst_port'] = "0"
                    
                    asn_info = get_asn(dst)
                    if asn_info:
                        dst_geo.update(asn_info)

                    batch.add_destination(dst_geo)
                    if dst_geo.get('country'):
                        batch.add_country_stat(dst_geo['country'])
                    enriched_data = dst_geo

    # LOG ENTRY (Separate Firewalls from System Logs)
    log_key = state.KEY_FIREWALL_LOGS if category == "Firewall" else state.KEY_LOGS

    fast_uuid = f"{time.time()}-{len(raw_msg)}-{random.randint(0, 1000000)}"
    log_payload = {
        "time": timestamp_str, "host": hostname, "msg": raw_msg[:5000],
        "priority": "high" if sys_anomaly_score > 3 else "low", 
        "uuid": fast_uuid,
        "is_security_event": is_sec, "anomaly_score": sys_anomaly_score,
        "category": category
    }
    log_payload.update(enriched_data)
    batch.add_log(log_key, log_payload)


# --- REPLACEMENT FUNCTION ---
def process_batch_cpu_bound(messages):
    """
    Runs in a separate thread. Processes the entire list linearly.
    This avoids the massive overhead of creating 2000 separate tasks.
    """
    batch = BatchAccumulator()
    for msg in messages:
        # We run the parse logic directly here
        res = parse_log_entry(msg)
        if not res: continue
        
        # Aggregate immediately
        batch.counts.update(res['counts'])
        for k, v in res['stat_inc'].items():
            for field, amt in v.items(): batch.inc_stat(k, field, amt)
        if res['log']: batch.add_log(state.KEY_LOGS, res['log'])
        if res['scatter']: batch.add_log(state.KEY_NETFLOW_SCATTER, res['scatter'])
        if res['sudo']: batch.add_log(state.KEY_SUDO_CMDS, res['sudo'])
        if res['major_anomaly']: batch.add_log(state.KEY_MAJOR_ANOMALIES, res['major_anomaly'])
        for nid, data in res['topo_node'].items(): batch.update_topo_node(nid, data)
        for k, ltype in res['topo_link'].items(): batch.update_topo_link(*k.split('-'), ltype)
        if res['user']: batch.update_user(*res['user'])
        if res['host']: batch.update_host(*res['host'])
        if res['map']: batch.update_map(*res['map'])
        if res['global_anomaly_score'] > 0:
            # Note: We can't update state directly in a thread safely without locking, 
            # but for simple counters usually it's fine, OR return this data to main thread.
            # For safety, we will return these sums.
            pass 
            
    return batch, state.current_global_anomaly_sum, state.current_global_anomaly_count

# 1. Helper to split list into chunks
def chunk_list(data, num_chunks):
    k, m = divmod(len(data), num_chunks)
    return (data[i * k + min(i, m):(i + 1) * k + min(i + 1, m)] for i in range(num_chunks))

# 2. Renamed function (logic is the same as previous step, just renamed for clarity)
def process_batch_chunk(messages):
    """
    Runs in a separate thread. Processes a CHUNK of the batch.
    """
    batch = BatchAccumulator()
    local_anomaly_sum = 0
    local_anomaly_count = 0
    
    # DEBUG: Track if we are actually seeing traffic
    traffic_seen = 0
    
    for msg in messages:
        res = parse_log_entry(msg)
        if not res: continue
        
        # Aggregate into local batch
        batch.counts.update(res['counts'])
        for k, v in res['stat_inc'].items():
            for field, amt in v.items(): batch.inc_stat(k, field, amt)
            
        if res['log']: batch.add_log(state.KEY_LOGS, res['log'])
        if res['scatter']: batch.add_log(state.KEY_NETFLOW_SCATTER, res['scatter'])
        if res['sudo']: batch.add_log(state.KEY_SUDO_CMDS, res['sudo'])
        if res['major_anomaly']: batch.add_log(state.KEY_MAJOR_ANOMALIES, res['major_anomaly'])
        
        # --- TOPOLOGY FIX ---
        for nid, data in res['topo_node'].items(): 
            batch.update_topo_node(nid, data)

        # Handle Links safely (No split!)
        for key, ltype in res['topo_link'].items():
            # If the key is just the string, we can split it safely here 
            # OR better yet, let parse_log_entry pass tuples if we changed it.
            # For now, let's wrap this in a try/except so one bad link doesn't kill the batch
            try:
                src, dst = key.split('-')
                batch.update_topo_link(src, dst, ltype)
                traffic_seen += 1
            except ValueError:
                print("IGNORED!!")
                pass # Ignore malformed keys
                
        if res['user']: batch.update_user(*res['user'])
        if res['host']: batch.update_host(*res['host'])
        if res['map']: batch.update_map(*res['map'])
        
        if res['global_anomaly_score'] > 0:
            local_anomaly_sum += res['global_anomaly_score']
            local_anomaly_count += 1
            
    # DEBUG: Print once per batch if we saw traffic (check your console!)
    if traffic_seen > 0:
        print(f"✅ Chunk processed: {traffic_seen} links found.")
            
    return batch, local_anomaly_sum, local_anomaly_count

# 3. Optimized Kafka Worker (True Parallel Processing)
def fetch_and_process_batch(consumer, batch_size, timeout, processor=process_log_into_batch):
    # 1. Fetch (Releases GIL internally in C-library)
    msgs = consumer.consume(batch_size, timeout)
    if not msgs:
        return None

    # 2. Parallel Processing (CPU Bound)
    # Split the messages into smaller chunks for parallel parsing
    num_threads = 8  # Use a portion of the worker pool
    chunk_count = len(msgs)
    chunk_size = max(1, chunk_count // num_threads)
    chunks = [msgs[i:i + chunk_size] for i in range(0, chunk_count, chunk_size)]
    
    def process_chunk(msg_chunk):
        local_batch = BatchAccumulator()
        count = 0
        for m in msg_chunk:
            if not m.error():
                processor(m.value(), local_batch)
                count += 1
        return local_batch, count

    # Submit chunks to the thread pool for simultaneous processing
    futures = [thread_pool.submit(process_chunk, c) for c in chunks]
    
    # 3. Aggregate Results
    main_batch = BatchAccumulator()
    total_count = 0
    for future in futures:
        try:
            lb, count = future.result()
            total_count += count
            
            # Efficiently merge local results into the main batch
            main_batch.counts.update(lb.counts)
            
            for k, v in lb.stats_inc.items():
                for field, amt in v.items(): main_batch.inc_stat(k, field, amt)
            
            for k, v in lb.list_push.items():
                main_batch.list_push[k].extend(v)
            
            for k, v in lb.threat_stats.items():
                main_batch.inc_threat_stat(k, v)
                
            main_batch.destinations.extend(lb.destinations)
            main_batch.anomaly_entries.extend(lb.anomaly_entries)
            
            main_batch.country_activity.update(lb.country_activity)
            main_batch.attack_country_activity.update(lb.attack_country_activity)
            
            # Complex Objects
            for nid, node_data in lb.topo_nodes.items():
                main_batch.update_topo_node(nid, node_data)
                
            for link_key, link_data in lb.topo_links.items():
                src, dst = link_key.split('-')
                main_batch.update_topo_link(src, dst, link_data['type'])
                
            for host_id, h_data in lb.host_activity.items():
                main_batch.update_host(host_id, False, h_data['score'], reason=h_data['reason'], sent=h_data['sent'], received=h_data['received'])

            for user_id, u_data in lb.user_activity.items():
                for h in u_data['hosts']:
                    main_batch.update_user(user_id, h)
            
            main_batch.map_updates.update(lb.map_updates)
            
        except Exception as e:
            print(f"Parallel Parsing Error: {e}")
            import traceback
            traceback.print_exc()
            
    return (main_batch, total_count) if total_count > 0 else None

async def kafka_worker_generic(topic, conf, label, eps_key, processor=process_log_into_batch):
    # Generate a unique group ID for this specific worker to ensure it starts at the latest offset
    # and doesn't conflict with other workers or previous runs.
    worker_conf = conf.copy()
    worker_conf['group.id'] = f"{conf.get('group.id', 'generic_worker')}_{uuid.uuid4().hex[:8]}"
    
    try:
        consumer = Consumer(worker_conf)
        consumer.subscribe([topic])
        print(f"🚀 {label} Backend Started (Threaded Processing Mode)...{topic} Group: {worker_conf['group.id']}")
        loop = asyncio.get_running_loop()
        
        while True:
            fetch_start = time.perf_counter()
            
            # --- CRITICAL CHANGE ---
            # We run BOTH fetch AND parse in the thread pool.
            # This prevents the parsing loop from blocking the WebSocket.
            result = await loop.run_in_executor(
                thread_pool, 
                fetch_and_process_batch, 
                consumer, 
                5000, 
                0.5,
                processor
            )
            
            if result:
                batch, msg_count = result
                
                # --- PERFORMANCE FIX: Threaded Commit ---
                # Move synchronous Redis operations to thread pool to keep main loop free
                loop.run_in_executor(thread_pool, state.commit_batch, batch)

                dt = max(time.perf_counter() - fetch_start, 0.001)
                rate = msg_count / dt
                # Smooth per component
                current = state.eps_components[eps_key]
                state.eps_components[eps_key] = (0.2 * rate) + (0.8 * current)
            else:
                # Decay if no traffic
                current = state.eps_components[eps_key]
                state.eps_components[eps_key] = 0.9 * current
                await asyncio.sleep(0.01) # Short sleep to yield control
                
    except Exception as e:
        print(f"Kafka Error: {e}")
        traceback.print_exc()

async def metric_worker():
    while True:
        # Sum all components for total EPS
        total_eps = sum(state.eps_components.values())
        state.live_eps = total_eps # For snapshot compatibility
        
        state.smoothed_eps = total_eps # Components are already smoothed
        state.push_log(state.KEY_EPS_HISTORY, {"time": time.strftime('%H:%M:%S'), "eps": int(state.smoothed_eps)}, max_len=60)
        
        if state.current_global_anomaly_count > 0:
            avg = state.current_global_anomaly_sum / state.current_global_anomaly_count
            state.push_log(state.KEY_ANOMALY_HISTORY, {"time": time.strftime('%H:%M:%S'), "avg_score": round(avg, 2)}, max_len=60)
            state.current_global_anomaly_sum = 0
            state.current_global_anomaly_count = 0
        
        await asyncio.sleep(1)

class VulnerabilityRequestBroker:
    def __init__(self, cve_cache):
        self.queue = asyncio.Queue()
        self.cve_cache = cve_cache
        self.processed_requests = {}
    async def worker(self, client):
        while True:
            search_query, event = await self.queue.get()
            if search_query in self.cve_cache: cves_data = self.cve_cache[search_query]
            else:
                encoded = urllib.parse.quote(search_query)
                try:
                    resp = await client.get(f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={encoded}")
                    cves_data = resp.json() if resp.status_code == 200 else {"vulnerabilities": []}
                    self.cve_cache[search_query] = cves_data
                except: cves_data = {"vulnerabilities": []}
                await asyncio.sleep(8)
            self.processed_requests[search_query] = cves_data
            event.set()
            self.queue.task_done()
    async def request_vulnerabilities(self, search_query):
        if search_query in self.processed_requests: return self.processed_requests[search_query]
        if search_query in self.cve_cache: return self.cve_cache[search_query]
        event = asyncio.Event()
        await self.queue.put((search_query, event))
        await event.wait()
        return self.processed_requests[search_query]

async def get_llm_analysis(device_name, model, os_info, cves):
    """
    Calls the LLM to analyze the risk of specific CVEs on a specific device.
    """
    try:
        cve_list = "\n".join([f"- {c['id']}: {c['description']} (Score: {c['score']})" for c in cves])
        prompt = f"Analyze the security risk for device '{device_name}' (Model: {model}, OS: {os_info}).\n\nThe following vulnerabilities were found:\n{cve_list}\n\nProvide a concise assessment of the impact and recommended actions."

        async with httpx.AsyncClient(verify=False) as client:
            json_data = {
                "model": "google/gemma-3-27b-it",
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.1,
                "max_tokens": 2048
            }
            resp = await client.post("http://10.250.133.8:8080/vllm-gemma3-27b/v1/chat/completions", json=json_data, timeout=60)
            if resp.status_code == 200:
                return resp.json().get("choices", [{}])[0].get("message", {}).get("content", "Analysis unavailable.")
            return f"LLM Error: {resp.status_code}"
    except Exception as e:
        return f"Analysis failed: {str(e)}"

async def process_device(device, client, cve_cache, llm_analysis_cache, broker):
    device_name = device.get("name") or f"Device-{device.get('id')}"
    platform = device.get("platform")
    model = device.get("device_type", {}).get("model") or "Unknown Model"
    
    if not platform: 
        print(f"      ⏭️ Skipping {device_name}: No platform info")
        return {
            "device_name": device_name, 
            "is_vulnerable": False, 
            "device_type": model, 
            "highest_severity_score": 0,
            "cves": [],
            "llm_analysis": "No platform info available.",
            "reason": "No platform"
        }
    
    os_name = platform.get("name")
    os_version = device.get("custom_fields", {}).get("os_build")
    
    if not os_name:
        print(f"      ⏭️ Skipping {device_name}: OS Name missing")
        return {
            "device_name": device_name, 
            "is_vulnerable": False, 
            "device_type": model, 
            "highest_severity_score": 0,
            "cves": [],
            "llm_analysis": "OS name missing from Netbox.",
            "reason": "OS name missing"
        }

    if not os_version:
        # Fallback to model if os_version is missing
        search_query = f"{os_name} {model}"
        print(f"      ⚠️ {device_name}: OS Version (os_build) missing, using model for search: {search_query}")
    else:
        search_query = f"{os_name} {os_version}"
        # Refine search query
        match = re.search(r"^(\w+)\s+([\w-]+)\s+(\d+\.\d+)", os_name)
        if match: search_query = f"{match.group(1)} {match.group(3)}"
    
    try:
        cves_data = await broker.request_vulnerabilities(search_query)
        cves = cves_data.get("vulnerabilities", [])
        device_cves = []
        highest = 0
        for item in cves:
            cve = item.get("cve", {})
            metrics = cve.get("metrics", {}).get("cvssMetricV31", [])
            if metrics:
                score = metrics[0].get("cvssData", {}).get("baseScore", 0)
                if score > highest: highest = score
                device_cves.append({
                    "id": cve.get("id"), 
                    "description": cve.get("descriptions", [{}])[0].get("value"), 
                    "score": score, 
                    "severity": metrics[0].get("cvssData", {}).get("baseSeverity", "UNKNOWN")
                })
        
        llm_analysis = "No vulnerabilities detected. No analysis required."
        if device_cves:
            key = f"{device_name}-{'-'.join(sorted([c['id'] for c in device_cves]))}"
            if key in llm_analysis_cache: 
                llm_analysis = llm_analysis_cache[key]
            else:
                llm_analysis = await get_llm_analysis(device_name, model, f"{os_name} {os_version or ''}", device_cves)
                llm_analysis_cache[key] = llm_analysis
        
        return { 
            "device_name": device_name, 
            "os": f"{os_name} {os_version or ''}", 
            "device_type": model, 
            "highest_severity_score": highest, 
            "cves": device_cves, 
            "is_vulnerable": len(device_cves) > 0, 
            "llm_analysis": llm_analysis 
        }
    except Exception as e:
        print(f"      ❌ Error processing {device_name}: {e}")
        return {
            "device_name": device_name, 
            "is_vulnerable": False, 
            "device_type": model, 
            "highest_severity_score": 0,
            "cves": [],
            "llm_analysis": f"Error: {str(e)}",
            "reason": f"Error: {str(e)}"
        }

async def update_vulnerabilities():
    global vulnerable_devices_cache
    print(f"🔍 NETBOX: Starting vulnerability scan for roles: {NETBOX_ROLES}")
    headers = {"Authorization": f"Token {NETBOX_TOKEN}", "Content-Type": "application/json", "Accept": "application/json"}
    cve_cache = load_cache(CVE_CACHE_FILE)
    llm_analysis_cache = load_cache(LLM_ANALYSIS_CACHE_FILE)
    broker = VulnerabilityRequestBroker(cve_cache)
    new_cache = {}
    async with httpx.AsyncClient(verify=False) as client:
        broker_task = asyncio.create_task(broker.worker(client))
        for role in NETBOX_ROLES:
            try:
                devices = []
                # Use slug for filtering if possible, or just the name as fallback
                url = f"{NETBOX_URL}/api/dcim/devices/?role={role.lower()}"
                print(f"  📡 Fetching devices for role '{role}' from {url}")
                while url:
                    resp = await client.get(url, headers=headers)
                    if resp.status_code == 200:
                        data = resp.json()
                        results = data.get("results", [])
                        devices.extend(results)
                        print(f"    ✅ Found {len(results)} devices for role '{role}'")
                        url = data.get("next") if data.get("next") else None
                    else: 
                        print(f"    ❌ Error fetching devices for role '{role}': {resp.status_code} {resp.text}")
                        break
                
                if devices:
                    tasks = [process_device(d, client, cve_cache, llm_analysis_cache, broker) for d in devices]
                    results = await asyncio.gather(*tasks)
                    new_cache[role] = sorted(results, key=lambda x: x.get("highest_severity_score", 0), reverse=True)
                    print(f"    ✅ Processed {len(results)} devices for role '{role}'")
                else:
                    new_cache[role] = []
                    print(f"    ⚠️ No devices found for role '{role}'")
                    
            except Exception as e: 
                print(f"  ❌ Netbox Error {role}: {e}")
                traceback.print_exc()
        await broker.queue.join()
        broker_task.cancel()
    vulnerable_devices_cache = new_cache
    save_cache(CVE_CACHE_FILE, cve_cache)
    save_cache(LLM_ANALYSIS_CACHE_FILE, llm_analysis_cache)
    await get_overall_summary([d for role in new_cache.values() for d in role])

async def get_overall_summary(devices):
    global overall_summary_cache
    vuln = [d for d in devices if d.get("is_vulnerable")]
    if not vuln:
        overall_summary_cache = "No vulnerable devices detected to summarize."
        return

    print(f"📝 NETBOX: Generating overall summary for {len(vuln)} vulnerable devices...")
    summary_input = "\n".join([f"- {d['device_name']}: {d.get('llm_analysis')}" for d in vuln])
    try:
        async with httpx.AsyncClient(verify=False) as client:
            json_data = {
                "model": "google/gemma-3-27b-it",
                "messages": [{"role": "user", "content": f"Summarize the following security vulnerabilities found across our network infrastructure:\n{summary_input}" }],
                "temperature": 0.1,
                "max_tokens": 4096
            }
            resp = await client.post("http://10.250.133.8:8080/vllm-gemma3-27b/v1/chat/completions", json=json_data, timeout=120)
            if resp.status_code == 200:
                overall_summary_cache = resp.json().get("choices", [{}])[0].get("message", {}).get("content", "Summary unavailable.")
                save_cache(OVERALL_SUMMARY_CACHE_FILE, overall_summary_cache)
                print("  ✅ Overall summary updated.")
            else:
                print(f"  ❌ Summary LLM Error: {resp.status_code}")
    except Exception as e: 
        print(f"  ❌ Summary Generation Failed: {e}")

async def vulnerability_worker_loop():
    try:
        await update_vulnerabilities()
    except Exception as e:
        print(f"❌ Error in initial vulnerability scan: {e}")
    
    global INITIAL_SCAN_COMPLETE
    INITIAL_SCAN_COMPLETE = True
    print("✅ INITIAL_SCAN_COMPLETE set to True")
    while True:
        await asyncio.sleep(86400)
        try:
            await update_vulnerabilities()
        except Exception as e:
            print(f"❌ Error in scheduled vulnerability scan: {e}")

def gather_all_data():
    snap = state.get_snapshot()
    return {
        "metrics": {"eps": snap['metrics']['eps'], "counts": snap['metrics']['counts']},
        "anomalies": {"top": snap['anomalies']['top_hosts'], "major": snap['tables']['major_anomaly_events']},
        "netflow": {"causes": snap['netflow']['causes']}
    }

async def get_overall_analysis(data):
    print("DEBUG: Starting Overall Analysis LLM Call...")
    global overall_analysis_cache
    try:
        async with httpx.AsyncClient(verify=False) as client:
            json_data = {
                "model": "google/gemma-3-27b-it", # Verify this matches the name loaded in vLLM
                "messages": [{"role": "user", "content": f"Analyze the following security event data and provide a high-level summary of anomalies and threats:\n{json.dumps(data)}"}],
                #"messages": [{"role": "user", "content": f"You are a platform called Defence Halo. Given the information provided and the observables you have, describe in detail who you are and what you do.\n{json.dumps(data)}"}],
                "temperature": 0.1,
                "max_tokens": 8192 
            }
            resp = await client.post("http://10.250.133.8:8080/vllm-gemma3-27b/v1/chat/completions", json=json_data, timeout=300)
            
            if resp.status_code == 200:
                result = resp.json()
                content = result.get("choices", [{}])[0].get("message", {}).get("content")
                if content:
                    overall_analysis_cache = content
                    save_cache(OVERALL_ANALYSIS_CACHE_FILE, overall_analysis_cache)
                    print("DEBUG: Overall Analysis Updated Successfully.")
                else:
                    print(f"DEBUG: Unexpected LLM response format: {result}")
            else:
                 print(f"DEBUG: LLM Error {resp.status_code}: {resp.text}")
                 
    except Exception as e: 
        print(f"DEBUG: Overall Analysis Failed: {e}")
        traceback.print_exc()

async def overall_analysis_worker():
    while True:
        await get_overall_analysis(gather_all_data())
        await asyncio.sleep(300)

@app.get("/status")
async def get_status(): return {"initial_scan_complete": INITIAL_SCAN_COMPLETE}

@app.get("/netbox/vulnerabilities")
async def get_netbox_vulnerabilities(role: str = None): return vulnerable_devices_cache.get(role, []) if role else []
@app.get("/netbox/overall-summary")
async def get_overall_summary_endpoint(): return overall_summary_cache
@app.get("/overall-analysis")
async def get_overall_analysis_endpoint(): return overall_analysis_cache

def read_platform_docs():
    """Reads project documentation and system prompt to provide platform knowledge."""
    docs = ""
    try:
        # Load core identity/instructions
        if os.path.exists("chat_system_prompt.txt"):
            with open("chat_system_prompt.txt", "r") as f:
                docs += f"\n--- AI System Identity ---\n{f.read()}"
        
        # Load platform specs
        if os.path.exists("GEMINI.md"):
            with open("GEMINI.md", "r") as f:
                docs += f"\n--- Platform Technical Specs (GEMINI.md) ---\n{f.read()}"
        if os.path.exists("README.md"):
            with open("README.md", "r") as f:
                docs += f"\n--- Platform Overview (README.md) ---\n{f.read()}"
    except Exception as e:
        print(f"Error reading platform docs: {e}")
    return docs

class ChatRequest(BaseModel):
    message: str
    context: dict = None

@app.post("/chat")
async def chat_endpoint(request: ChatRequest):
    try:
        platform_knowledge = read_platform_docs()
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Enrich context with latest data from Redis if not provided or to ensure fresh data
        enhanced_context = request.context or {}
        if not enhanced_context.get('recent_netflow_stats'):
            fresh_data = gather_all_data()
            enhanced_context['recent_netflow_stats'] = fresh_data.get('netflow', {}).get('causes')

        # System prompt is now primarily derived from files
        system_prompt = f"You are the Defense Halo AI assistant. Current system time is {current_time}."
        
        if platform_knowledge:
            system_prompt += f"\n\nKnowledge Base & Identity:\n{platform_knowledge}"
        
        if enhanced_context:
            system_prompt += f"\n\nCurrent Dashboard Context (Real-time data): {json.dumps(enhanced_context)}"

        async with httpx.AsyncClient(verify=False) as client:
            json_data = {
                "model": VLLM_MODEL,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": request.message}
                ],
                "temperature": 0.2,
                "max_tokens": 1024
            }
            resp = await client.post(VLLM_ENDPOINT, json=json_data, timeout=60)
            
            if resp.status_code == 200:
                result = resp.json()
                return {"response": result.get("choices", [{}])[0].get("message", {}).get("content", "I'm sorry, I couldn't generate a response.")}
            else:
                return {"response": f"Error from AI backend: {resp.status_code}"}
    except Exception as e:
        return {"response": f"Chat failed: {str(e)}"}

@app.get("/host/{host_id}/history")
async def get_host_history_endpoint(host_id: str):
    return state.get_host_history(host_id)

@app.get("/host/{host_id}/anomaly-logs")
async def get_host_anomaly_logs_endpoint(host_id: str):
    return state.get_host_anomaly_logs(host_id)

@app.get("/host/{host_id}/ports")
async def get_host_ports_endpoint(host_id: str):
    port_raw = state.r.hgetall(f"morpheus:host:{host_id}:ports")
    return list(port_raw.keys()) if port_raw else []

@app.get("/hosts")
async def get_all_hosts_endpoint():
    return state.get_all_hosts()

@app.post("/reset")
async def reset_dashboard():
    state.reset_all()
    return {"status": "reset_complete", "message": "All dashboard counters and history have been cleared."}

async def host_history_worker():
    print("📈 HOST HISTORY: Worker started (10 min interval)...")
    # Initial recording on startup
    state.record_host_history()
    while True:
        await asyncio.sleep(600) # 10 minutes
        state.record_host_history()

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    await websocket.send_json({"type": "status", "status": "connected"})
    
    loop = asyncio.get_running_loop()
    ws_state = {"show_external": False}
    
    async def listen_for_messages():
        try:
            while True:
                data = await websocket.receive_text()
                parsed = json_loads(data)
                if parsed.get('type') == 'filter_update':
                    ws_state["show_external"] = parsed.get('show_external', False)
                    print(f"DEBUG: WebSocket Filter Update - show_external={ws_state['show_external']}")
        except: pass

    # Run listener in background
    listen_task = asyncio.create_task(listen_for_messages())
    is_active = True
    
    try:
        while is_active:
            # 1. OPTIMIZED: Use Cached Snapshot
            # Fallback to direct calculation if worker hasn't run yet
            if ws_state["show_external"]:
                snapshot = state.cached_snapshot_external or await loop.run_in_executor(thread_pool, partial(state.get_snapshot, show_external=True))
            else:
                snapshot = state.cached_snapshot or await loop.run_in_executor(thread_pool, partial(state.get_snapshot, show_external=False))
            
            # 2. Update EPS (from latest live state)
            snapshot['metrics']['eps'] = round(state.smoothed_eps, 1)

            # 3. SERIALIZATION
            # We skip JSON re-serialization if we want to be even faster, but snapshots change slightly (EPS).
            json_str = json_dumps(snapshot)

            # 4. SEND AS TEXT (With safety check)
            if is_active:
                await websocket.send_text(json_str)
            
            # 5. Throttle
            await asyncio.sleep(3.0) 
            
    except (WebSocketDisconnect, ConnectionClosed):
        is_active = False
        print("INFO: WebSocket client disconnected.")
    except Exception as e:
        is_active = False
        if "websocket.send" not in str(e): # Ignore expected late-send errors
            print(f"WebSocket Error: {e}")
            traceback.print_exc()
    finally:
        is_active = False
        listen_task.cancel()

async def dns_janitor_worker():
    print("🕵️ DNS Janitor: Started background resolution service...")
    while True:
        try:
            # 1. Get all current topology nodes from Redis
            nodes_raw = state.r.hgetall(state.KEY_TOPO_NODES)
            
            # 2. Identify unresolved IPs
            to_resolve = []
            
            for nid, data in nodes_raw.items():
                try:
                    node = json_loads(data)
                    # Simple Regex for IPv4
                    if (node['id'] == node.get('name') and 
                        not node.get('dns_checked') and 
                        re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", nid)):
                        to_resolve.append(nid)
                except: continue

            # 3. Limit batch size
            batch = to_resolve[:500]
            
            if batch:
                # Create async tasks for the batch running in the DNS pool
                loop = asyncio.get_running_loop()
                tasks = []
                for ip in batch:
                    tasks.append(loop.run_in_executor(dns_pool, socket.gethostbyaddr, ip))

                # Run them concurrently
                results = await asyncio.gather(*tasks, return_exceptions=True)

                # 4. Process Results and Update Redis
                for i, result in enumerate(results):
                    ip = batch[i]
                    update_data = {'dns_checked': True} 
                    
                    if not isinstance(result, Exception):
                        hostname = result[0]
                        update_data['name'] = hostname

                    # Direct update to Redis using existing method
                    state.update_topology_node_direct(ip, update_data)

        except Exception as e:
            print(f"DNS Janitor Error: {e}")
            
        # Sleep to be polite to the CPU
        await asyncio.sleep(2.0)

# --- NETBOX IPAM INTEGRATION ---
netbox_prefix_cache = []

import unicodedata
import re

def slugify(value):
    """
    Helper: Generates a slug from a name if the API doesn't provide one.
    e.g. "LON8 (Site)" -> "lon8-site"
    """
    value = str(value)
    value = unicodedata.normalize('NFKD', value).encode('ascii', 'ignore').decode('ascii')
    value = re.sub(r'[^\w\s-]', '', value.lower())
    return re.sub(r'[-\s]+', '-', value).strip('-')

async def update_netbox_prefixes():
    """
    Fetches ALL prefixes (Containers & Child Subnets).
    Prioritizes 'Scope' > 'Site' > 'Tenant'.
    """
    global netbox_prefix_cache
    headers = {"Authorization": f"Token {NETBOX_TOKEN}", "Content-Type": "application/json", "Accept": "application/json"}
    
    print("🌍 NETBOX: Starting Full IPAM Sync (Targeting Child Subnets)...")
    new_cache = []
    
    try:
        async with httpx.AsyncClient(verify=False) as client:
            # limit=0 is MANDATORY to fetch the thousands of child /27s
            url = f"{NETBOX_URL}/api/ipam/prefixes/?limit=0"
            resp = await client.get(url, headers=headers)
            
            if resp.status_code == 200:
                data = resp.json()
                results = data.get("results", [])
                
                count_scoped = 0
                count_sited = 0
                
                for item in results:
                    prefix_str = item.get("prefix")
                    if not prefix_str: continue

                    site_slug = None
                    site_name = None
                    
                    # --- LOCATION DETECTION LOGIC ---
                    
                    # 1. Check 'Scope' (New NetBox Standard) - PRIORITIZED
                    # We handle cases where 'slug' might be missing
                    scope = item.get("scope")
                    if scope:
                        site_name = scope.get("name")
                        site_slug = scope.get("slug") or slugify(site_name)
                        count_scoped += 1
                        
                    # 2. Check 'Site' (Legacy Standard)
                    elif item.get("site"):
                        site = item.get("site")
                        site_name = site.get("name")
                        site_slug = site.get("slug") or slugify(site_name)
                        count_sited += 1

                    # 3. Fallback: Check 'Tenant' (for Containers)
                    elif item.get("tenant"):
                        tenant = item.get("tenant")
                        site_name = tenant.get("name")
                        site_slug = tenant.get("slug") or slugify(site_name)

                    # --- STORE VALID MAPPINGS ---
                    if site_slug and site_name:
                        try:
                            net = ipaddress.ip_network(prefix_str)
                            new_cache.append((net, site_slug, site_name))
                            
                            # DEBUG: Watch for your specific example
                            if "10.250.47" in prefix_str:
                                print(f"   🎯 TARGET ACQUIRED: {prefix_str} -> {site_name} (via Scope)")
                                
                        except ValueError:
                            continue

                # --- CRITICAL: LONGEST PREFIX MATCH SORTING ---
                # This ensures the /27 (LON8) is checked BEFORE the /16 (Container)
                new_cache.sort(key=lambda x: x[0].prefixlen, reverse=True)
                get_site_for_ip.cache_clear()

                netbox_prefix_cache = new_cache
                print(f"✅ NETBOX SYNC COMPLETE:")
                print(f"   - Loaded {len(new_cache)} total subnets")
                print(f"   - Found {count_scoped} prefixes using 'Scope'")
                print(f"   - Found {count_sited} prefixes using 'Site'")
                print(f"   - Longest Prefix Match is ACTIVE.")
            else:
                print(f"❌ NETBOX: API Error {resp.status_code}")
    except Exception as e:
        print(f"❌ NETBOX: Sync Error: {e}")

async def threat_score_worker():
    print("🛡️ THREAT SCORE: Worker started (5 min interval)...")
    while True:
        try:
            # 1. Fetch Accumulators
            raw = state.r.hgetall(state.KEY_THREAT_ACCUM)
            if raw:
                # 2. Reset Accumulators immediately to start next window
                state.r.delete(state.KEY_THREAT_ACCUM)
                
                stats = {k: float(v) for k, v in raw.items()}
                
                # 3. Calculate Components
                sys_score = stats.get('sys_sum', 0) / max(stats.get('sys_count', 1), 1)
                net_score = stats.get('net_sum', 0) / max(stats.get('net_count', 1), 1)
                
                # Auth Score: 100 fails = 10.0
                auth_count = stats.get('auth_fail', 0)
                auth_score = min(auth_count / 10.0, 10.0)
                
                # 4. Overall Score
                final_score = (sys_score + net_score + auth_score) / 3.0
                final_score = min(max(final_score, 0.0), 10.0) # Clamp 0-10
                
                print(f"🛡️ THREAT UPDATE: Sys={sys_score:.2f}, Net={net_score:.2f}, Auth={auth_count} -> Final={final_score:.2f}")
                
                # 5. Publish
                next_update = time.time() + 300
                payload = {
                    "score": round(final_score, 1),
                    "next_update": next_update,
                    "components": {
                        "system": round(sys_score, 1),
                        "network": round(net_score, 1),
                        "auth": round(auth_score, 1)
                    }
                }
                state.r.set(state.KEY_THREAT_SCORE, json_dumps(payload))
            else:
                # No data yet, just set next update
                next_update = time.time() + 300
                payload = {"score": 0.0, "next_update": next_update}
                # Only set if not exists, to preserve timer on restart if persistence is desired
                if not state.r.exists(state.KEY_THREAT_SCORE):
                    state.r.set(state.KEY_THREAT_SCORE, json_dumps(payload))
                
        except Exception as e:
            print(f"Threat Worker Error: {e}")
            
        await asyncio.sleep(300) # Wait 5 minutes for next window

async def global_snapshot_worker():
    print("💎 SNAPSHOT: Background refresh worker started (3s interval)...")
    while True:
        try:
            # We run this heavy Redis scan in a separate thread to not block other workers
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(thread_pool, state.refresh_global_snapshot)
        except Exception as e:
            print(f"Snapshot Worker Error: {e}")
        await asyncio.sleep(3.0)

async def passive_decay_worker():
    print("⏳ DECAY: Anomaly healing worker started (10s interval)...")
    while True:
        try:
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(thread_pool, state.perform_passive_decay)
        except Exception as e:
            print(f"Decay Worker Error: {e}")
        await asyncio.sleep(10.0)

async def janitor_worker():
    print("🧹 JANITOR: Database pruning worker started (1m interval)...")
    while True:
        try:
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(thread_pool, state.cleanup_stale_data)
        except Exception as e:
            print(f"Janitor Worker Error: {e}")
        await asyncio.sleep(60.0)

@app.on_event("startup")
async def startup_event():
    print("🚀 STARTUP: Application starting...")
    asyncio.create_task(kafka_worker_generic(TOPIC_SECURITY, KAFKA_CONF_SECURITY, "Security", "security"))
    asyncio.create_task(kafka_worker_generic(TOPIC_NETFLOW, KAFKA_CONF_NETFLOW, "Netflow DFP", "netflow"))
    asyncio.create_task(metric_worker())
    asyncio.create_task(vulnerability_worker_loop())
    asyncio.create_task(overall_analysis_worker())
    asyncio.create_task(threat_score_worker())
    asyncio.create_task(host_history_worker())
    asyncio.create_task(dns_janitor_worker())
    asyncio.create_task(update_netbox_prefixes())
    asyncio.create_task(global_snapshot_worker())
    asyncio.create_task(passive_decay_worker())
    asyncio.create_task(janitor_worker())
    print("✅ STARTUP: All tasks launched.")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5174)
