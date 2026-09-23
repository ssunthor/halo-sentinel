# Defense Halo — Customer CVE Analyzer (Backend)

FastAPI service that inventories devices from NetBox, queries the NIST NVD for CVE data, and uses a vLLM endpoint to generate per-device and estate-level security assessments. Results are persisted in SQLite and served via REST + Server-Sent Events (SSE) to the React frontend.

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Data Model](#data-model)
4. [Scanning Process](#scanning-process)
   - [Per-Tenant Scan](#per-tenant-scan)
   - [Global Scan (All Tenants)](#global-scan-all-tenants)
   - [NVD CVE Lookup](#nvd-cve-lookup)
5. [AI Inference Process](#ai-inference-process)
   - [Per-Device Analysis](#per-device-analysis)
   - [Estate Summary](#estate-summary)
   - [Background Back-Fill Worker](#background-back-fill-worker)
6. [API Reference](#api-reference)
7. [Configuration](#configuration)
8. [Running Locally](#running-locally)
9. [Docker](#docker)

---

## Overview

The backend is a single FastAPI application (`main.py`) with a companion persistence module (`db.py`). It is designed to:

- Connect to a **NetBox** CMDB to enumerate devices and virtual machines across one or all tenants
- Query the **NIST National Vulnerability Database (NVD) API v2** for CVEs relevant to each device's OS/platform
- Call a **vLLM-hosted language model** to produce human-readable security analysis at the device and estate level
- Serve scan results live via **Server-Sent Events** and persist them in a **SQLite WAL-mode database**
- Expose a leaderboard, estate statistics, and Excel export endpoints for the frontend

Everything is configuration-driven via environment variables — no code changes are needed to point at a different NetBox instance, LLM endpoint, or Redis host.

---

## Architecture

```
NetBox CMDB
    │  REST API (devices, VMs, tenants, custom fields)
    ▼
┌─────────────────────────────────────────────────────┐
│                    main.py (FastAPI)                 │
│                                                      │
│  ┌─────────────────┐   ┌──────────────────────────┐ │
│  │  Per-Tenant Scan │   │      Global Scan         │ │
│  │  run_tenant_scan │   │      run_global_scan     │ │
│  └────────┬────────┘   └───────────┬──────────────┘ │
│           │                        │                 │
│           └──────────┬─────────────┘                 │
│                      ▼                               │
│         VulnerabilityRequestBroker                   │
│         (serialises NVD API calls,                   │
│          10s sleep between hits,                     │
│          in-memory cache for results)                │
│                      │                               │
│                      ▼                               │
│             NVD API v2 (nvd.nist.gov)                │
│                      │                               │
│            CVE data per platform/version             │
│                      │                               │
│           ┌──────────┴──────────┐                   │
│           │  llm_interface.py   │                   │
│           │  vLLMClient         │                   │
│           │  (Keycloak auth or  │                   │
│           │   static token)     │                   │
│           └──────────┬──────────┘                   │
│                      │                               │
│             vLLM endpoint (Gemma-3 27B or similar)   │
│                      │                               │
│           ┌──────────▼──────────┐                   │
│           │       db.py         │                   │
│           │   SQLite WAL-mode   │                   │
│           │  tenants / devices  │                   │
│           │  cves / summaries   │                   │
│           └─────────────────────┘                   │
│                                                      │
│  Background workers (asyncio tasks):                 │
│  • llm_analysis_worker  — back-fills AI analysis     │
│    for bulk-scanned tenants                          │
│                                                      │
│  SSE endpoints (/api/results/{id}/stream,            │
│                 /api/scan/global/stream)             │
└─────────────────────────────────────────────────────┘
         │  REST + SSE
         ▼
    React Frontend (nginx → backend proxy)

Redis  ←  scan progress counters (scanned / total / status)
```

---

## Data Model

The SQLite database lives at `/app/cache/cve_analyzer.db` (configured via `CACHE_DIR` env var). It uses WAL mode for concurrent reads and has a single write-serialisation lock (`_write_lock`).

### Tables

#### `tenants`

| Column | Type | Description |
|---|---|---|
| `tenant_id` | TEXT PK | NetBox tenant ID |
| `name` | TEXT | Tenant display name |
| `scanned_at` | TEXT | ISO-8601 timestamp of last scan |
| `bulk_scan` | INTEGER | 1 if populated by the global scan |
| `total_devices` | INTEGER | Device + VM count at scan time |
| `vulnerable_devices` | INTEGER | Devices with at least one CVE |
| `max_score` | REAL | Highest CVSS base score across all devices |

#### `devices`

| Column | Type | Description |
|---|---|---|
| `id` | INTEGER PK | Auto-increment |
| `tenant_id` | TEXT FK | References `tenants` |
| `resource_name` | TEXT | NetBox device/VM name |
| `resource_category` | TEXT | `device` or `vm` |
| `resource_type` | TEXT | Device model or cluster name |
| `os` | TEXT | Combined OS string (`platform_name os_version`) |
| `platform_name` | TEXT | OS/platform name from NetBox |
| `os_version` | TEXT | Firmware/OS version from custom fields |
| `recommended_version` | TEXT | Lowest NVD fix version that closes the device's remaining CVEs |
| `gia_recommended_version` | TEXT | GTT Engineering recommended version (GIA/DIU); set only when the device is behind it |
| `gia_component` | TEXT | Engineering approved-versions row the device was matched to, e.g. `Fortigate SD WAN Edge` |
| `serial` | TEXT | Serial number (devices only) |
| `pon` | TEXT | PON identifier from `cmd_pon` custom field |
| `highest_severity_score` | REAL | Max CVSS score across all CVEs |
| `is_vulnerable` | INTEGER | 1 if any CVEs found |
| `llm_analysis` | TEXT | LLM-generated security assessment |
| `scanned_at` | TEXT | ISO-8601 scan timestamp |

#### `cves`

| Column | Type | Description |
|---|---|---|
| `id` | INTEGER PK | Auto-increment |
| `device_id` | INTEGER FK | References `devices` |
| `cve_id` | TEXT | CVE identifier (e.g. `CVE-2024-12345`) |
| `score` | REAL | CVSS base score |
| `severity` | TEXT | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` |
| `description` | TEXT | English description from NVD |

#### `summaries`

| Column | Type | Description |
|---|---|---|
| `tenant_id` | TEXT PK | References `tenants` |
| `risk_posture` | TEXT | LLM classification: `Critical`/`High`/`Medium`/`Low`/`Clean` |
| `risk_summary` | TEXT | One-sentence estate risk statement |
| `trend` | TEXT | `improving`/`declining`/`stable`/`new_scan` |
| `trend_detail` | TEXT | Explanation of trend vs previous scan |
| `recommendations_json` | TEXT | JSON array of prioritised remediation steps |
| `top_cves_json` | TEXT | JSON array of top CVE objects |
| `generated_at` | TEXT | ISO-8601 timestamp of this summary |
| `previous_generated_at` | TEXT | ISO-8601 timestamp of the prior summary |
| `vulnerable_device_count` | INTEGER | Snapshot count at generation time |
| `total_device_count` | INTEGER | Snapshot count at generation time |
| `max_severity_score` | REAL | Snapshot max score at generation time |

### Startup migration

At startup, `db.init_db()` runs:

1. `CREATE TABLE IF NOT EXISTS` for all four tables (safe for existing databases)
2. `ALTER TABLE devices ADD COLUMN` for any columns added after initial deployment (currently `platform_name`, `os_version`, `serial`, `pon`) — columns already present are silently skipped
3. A best-effort `UPDATE` to back-fill `platform_name` from the existing `os` field for pre-migration rows
4. `CREATE INDEX IF NOT EXISTS` for all indexes, with the `platform_name` index created after the migration step that guarantees the column exists

`db.migrate_from_json()` also runs at startup to import any `tenant_*_results.json` files that predate the SQLite migration.

---

## Scanning Process

### Per-Tenant Scan

**Trigger:** `POST /api/scan/{tenant_id}[?force=true]`

**Flow:**

1. **Cache check** — If a scan result exists and is less than 24 hours old, return `status: cached` immediately (skipped when `force=true`).
2. **Device inventory** — Fetch all active devices (`/api/dcim/devices/?tenant_id=...`) and virtual machines (`/api/virtualization/virtual-machines/?tenant_id=...`) from NetBox via paginated requests. Pages are followed by reading the `next` URL from each response; `follow_redirects=True` is required because NetBox's http→https redirect would otherwise silently terminate pagination.
3. **Skeleton push** — Immediately push all device names to the SSE queue as `"llm_analysis": "Scanning..."` entries so the frontend shows the full device list instantly.
4. **Concurrent CVE lookup** — Process all devices concurrently with `asyncio.Semaphore(20)`. For each device:
   - Extract platform name and OS version from NetBox fields (`platform.name`, `custom_fields.os_build` for devices, `custom_fields.os_version` for VMs)
   - Build an NVD keyword query via `_build_nvd_query()`, which strips embedded version numbers from platform names and normalises FortiOS-style version strings
   - Submit the query to `VulnerabilityRequestBroker` (see [NVD CVE Lookup](#nvd-cve-lookup))
   - If the first query returns no results, attempt a simplified query with a shortened version string (e.g. `7.4.2` → `7.4`)
5. **LLM analysis** — For each device with CVEs, call `get_llm_analysis()`. Results are cached in `llm_analysis_cache` (in-memory + persisted to `llm_analysis_cache.json`) keyed by `device_name-CVE_list_hash`.
6. **Persist** — Call `db.save_tenant_results()`, which opens a transaction, deletes existing device rows for the tenant, re-inserts the full result set, and updates the `tenants` row.
7. **Estate summary** — Call `generate_estate_summary()` to produce the LLM risk posture assessment for the whole tenant (see [Estate Summary](#estate-summary)).
8. **SSE close** — Push `{"type": "complete"}` to signal the frontend that the stream is done.

**Redis** is used to persist `status / scanned / total` counters so the `/api/scan/{id}/status` endpoint works correctly across requests even if the in-memory state has been cleared.

---

### Global Scan (All Tenants)

**Trigger:** `POST /api/scan/global`

The global scan is designed to process the entire estate (140,000+ devices across all tenants) in a single pass while making the minimum possible number of NVD API calls.

**Flow:**

#### Phase 1 — Device inventory

Fetch all devices and VMs across the entire NetBox instance without a tenant filter (`/api/dcim/devices/?limit=1000`, `/api/virtualization/virtual-machines/?limit=1000`). Pagination is followed automatically. Progress (`devices_fetched`, `physical_devices`, `virtual_machines`) is broadcast live via SSE.

#### Phase 2 — Platform deduplication

Build a `combo_map`: a dict mapping each unique `(NVD query string)` → `[list of raw NetBox device dicts]`.

- Devices with no platform or no OS version are collected separately in `no_platform` and written as score-0 records
- Devices sharing the same OS + version (e.g. 3,000 devices running "FortiOS 7.4.2") map to a single NVD query key, so the API is called exactly once for that combination
- Result: `unique_combos` (typically 200–2,000 distinct queries) vs `total_devices` (potentially 100,000+)

#### Phase 3 — NVD queries

All `combo_map` keys are submitted concurrently to `VulnerabilityRequestBroker` via `asyncio.gather()`. The broker's single worker serialises actual API calls with a 10-second sleep between each; cache hits are returned instantly. Progress (`nvd_queried`, `nvd_cached`) is broadcast live.

#### Phase 3b — Engineering recommended versions

If the inventory contains any Fortinet device, the GTT Engineering approved-versions table is loaded once from GIA (see [GTT Engineering Recommended Versions](#gtt-engineering-recommended-versions-giadiu)). Every device record built in Phase 4 is then matched to its engineering row in memory; no further GIA requests are made.

#### Phase 4 — Fan-out and save

CVE results are fanned back out to all matching devices, grouped by tenant, then saved to SQLite via `db.save_tenant_results()` for each tenant. The `bulk_scan` flag is set on each tenant row to indicate that per-device LLM analysis was deferred.

**Note:** The global scan intentionally skips per-device LLM analysis (which would require 100,000+ sequential API calls). The [Background Back-Fill Worker](#background-back-fill-worker) handles this asynchronously after the scan completes.

---

### NVD CVE Lookup

**`VulnerabilityRequestBroker`** serialises all NVD API requests to comply with the NIST rate limit (one unauthenticated request per 10 seconds by default).

- **Cache-first:** Before queuing any request, the broker checks the in-memory `cve_cache` dict (persisted to `cve_cache.json`). A cache hit is returned instantly with no delay.
- **Deduplication:** If multiple concurrent callers request the same query, only one HTTP request is made; all callers await the same `asyncio.Event` and receive the result simultaneously when it resolves.
- **Single worker:** One `asyncio.Task` drains the queue sequentially, sleeping 10 seconds between each real API call.
- **Query construction (`_build_nvd_query`):** Combines the NetBox platform name and OS version into an NVD keyword search string. Special cases:
  - FortiOS/FortiGate: extracts the `X.Y.Z` version from the build string
  - Platform names that embed a version number: the embedded version is removed to avoid redundancy (e.g. "IOS XE 17.x" + version "17.6.5" → `"IOS XE 17.6.5"`)
- **CVE parsing (`_parse_cve_response`):** Prefers CVSS v3.1 → v3.0 → v2 in that order. Only entries with a CVSS score are retained.

---

### GTT Engineering Recommended Versions (GIA/DIU)

Engineering keeps the software versions approved for production on the Confluence page _SD-WAN Software Version Control_. SERA's Data Inspector Utility (DIU) indexes that page, and GIA exposes it over REST at `${GIA_API_URL}/sam/diu` (the same API root that serves FBA under `/fba`, same `X-API-Key`). `gia_client.py` uses two of its calls:

- `GET /pages/search?query=SD-WAN Software Version Control&search_text=Fortinet Edges, Gateways, and Central Management Devices&expand=true` returns the page with only the matching section, whose `structured_tables_json` embeds the "Approved versions" tables.
- `GET /tables/{table_id}` fetches one table directly. It is the fallback (`GIA_TABLE_IDS`, default `6848998_SEC_42_TABLE_1,6848998_SEC_42_TABLE_2`) when the search returns no tables.

The section carries two tables: the live one, with a **GTT Preferred Version** column and an **Approved Date**, and an older one with only **New Deployments**. The client keeps the candidate with a GTT Preferred Version column and the most recent approval, and caches it in memory for `GIA_CACHE_TTL_HOURS` (default 24). A failed load is retried after `GIA_RETRY_MINUTES` (default 10); scans never wait on GIA.

Rows are per product role, not per NetBox platform, so each device is mapped to a row from its platform, model and NetBox role:

| NetBox evidence | Engineering row |
| --- | --- |
| Platform/model/role mention FortiManager or FortiAnalyzer | `FortiManager (Physical or VM)` / `FortiAnalyzer (Physical or VM)` |
| Model `FortiSwitch-…` (role mentions NID/monitoring) | `FortiSwitch (FortiLink)` (`FortiSwitch (Used as a Nid for monitoring)`) |
| Model `FortiAP-231F` etc. | The matching `FortiAP … (FortiLink)` row |
| Role mentions gateway/GW, SSE, or NFV | `Fortigate SD WAN Gateway`, `Fortigate SSE Node`, `Fortigate VM on NFV POD` |
| Model `FortiGate-VM64…` or a VM | `Fortigate SD WAN Edge (VM)` |
| Any other FortiGate/FortiWiFi (almost all have the generic role `CPE`) | `Fortigate SD WAN Edge`, falling back to the `Fortigate Edge (non SDWAN/ipsec) E/F series` row of its hardware |

The device's `x.y.z` (from `os_build`/`os_version`) is compared with the row's GTT Preferred Version. **Only a device that is behind it gets `gia_recommended_version` and `gia_component`**; a compliant device shows nothing, and a device whose version cannot be parsed is treated as behind. The dashboard shows the value as `Eng ★ 7.4.11` (row and detail view, with the engineering row in the tooltip); the Excel export has it in the _Eng Recommended Version_ column. Non-Fortinet devices are never looked up.

`GET /api/gia/status` shows the cached table (id, source, every row with its recommended version), when it was loaded, the last error, and match counters (`upgrade_needed`, `compliant`, `no_row`, per-component). `?reload=true` re-fetches the table immediately. `GIA_DEBUG=true` logs every request and every device → row decision.

---

## AI Inference Process

### Per-Device Analysis

**Function:** `get_llm_analysis(resource_name, model, os_info, cves)`

For each vulnerable device, a prompt is constructed that includes:

- Device name, model, and OS string
- Full list of CVEs with IDs, descriptions, and CVSS scores

The LLM is asked for a concise impact assessment and recommended remediation actions. The response is plain text (not JSON mode). Calls are executed via `loop.run_in_executor(thread_pool, ...)` so they never block the event loop or SSE streams.

Results are cached in `llm_analysis_cache` keyed by `"{device_name}-{sorted_cve_ids}"` and persisted to `llm_analysis_cache.json`. This means a device that appears in multiple scans (or across per-tenant and global scans) only ever requires one LLM call.

---

### Estate Summary

**Function:** `generate_estate_summary(tenant_id, tenant_name, devices)`

After a per-tenant scan completes (or after the back-fill worker finishes device analysis), an estate-level summary is generated. The prompt includes:

- Total device count, vulnerable device count, highest CVE score
- Top 30 most critical devices (name, OS, CVE count, highest score)
- Top 5 CVEs by frequency/severity with affected device counts
- If a previous summary exists: its `vulnerable_device_count` and `max_severity_score` for trend comparison

The LLM responds in **JSON mode** with the following schema:

```json
{
  "risk_posture": "Critical | High | Medium | Low | Clean",
  "risk_summary": "One-sentence estate risk statement",
  "top_cves": [{"id": "...", "score": 9.8, "severity": "CRITICAL", "affected_count": 12, "action": "..."}],
  "recommendations": ["Step 1", "Step 2", "..."],
  "trend": "improving | declining | stable | new_scan",
  "trend_detail": "One sentence comparing to the previous scan"
}
```

The result is saved to the `summaries` table and immediately returned to the frontend via the `GET /api/results/{id}/summary` endpoint.

---

### Background Back-Fill Worker

**Function:** `llm_analysis_worker()` — registered as an `asyncio.Task` at startup.

The global scan skips LLM calls for practicality. This worker continuously monitors the database for tenants and devices that still need analysis and fills them in asynchronously without overwhelming the vLLM endpoint.

**Rate limiting:**

| Control | Value | Effect |
|---|---|---|
| `asyncio.Semaphore(2)` | 2 concurrent calls | Caps in-flight LLM requests from the worker |
| `_LLM_WORKER_DEVICE_DELAY` | 3 seconds | Sleep after each real (non-cache) API call |
| `_LLM_WORKER_TENANT_DELAY` | 8 seconds | Sleep between finishing one tenant and starting the next |
| `_LLM_WORKER_IDLE_DELAY` | 120 seconds | Sleep when no tenants need work |
| `_LLM_WORKER_ERROR_DELAY` | 30 seconds | Sleep after an unexpected exception |

**Per-iteration logic:**

1. Query `db.get_tenants_needing_analysis(limit=20)` — returns tenants with no estate summary or with vulnerable devices whose `llm_analysis` is still a placeholder string from the bulk scan. Ordered by `vulnerable_devices DESC` so the most exposed clients are prioritised.
2. For each tenant, skip if an active per-tenant scan or global scan is running (to avoid write conflicts).
3. Load the full device list once (`db.load_tenant_results()`).
4. For each device needing analysis, check `llm_analysis_cache` first; if not cached, call `get_llm_analysis()` and sleep 3 seconds. Write the result to the database immediately via `db.update_device_llm_analysis()` (a single-row `UPDATE`, not a full tenant resave).
5. After all devices are processed, call `generate_estate_summary()`.

**Metrics** are tracked live in `_ai_stats` and exposed via `GET /api/ai/stats`:

- Status (starting / idle / analyzing / error)
- Current tenant and device name
- Pending queue depth (tenants + devices)
- Session totals: devices analyzed, real API calls, cache hits, errors
- Rolling latency stats over the last 100 API calls: average, P95, min, max
- 24-hour analyzed count (via a timestamp ring buffer)
- Cache hit rate percentage

---

## API Reference

All endpoints are prefixed with `/api/`. The frontend accesses them through nginx, which proxies `/api/` to `http://backend:5174/api/`.

### Tenants

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/tenants/search?q=&limit=50&devices_only=false` | Search NetBox tenants by name |
| `GET` | `/api/tenants/recent` | Tenants with local scan data, sorted by most recently scanned |
| `GET` | `/api/tenants` | Alias for `/api/tenants/search` (legacy compat) |

### Scanning

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/scan/{tenant_id}?tenant_name=&force=false` | Trigger or resume a per-tenant scan |
| `GET` | `/api/scan/{tenant_id}/status` | Scan progress: status, scanned, total |
| `GET` | `/api/results/{tenant_id}` | Full cached results for a tenant |
| `GET` | `/api/results/{tenant_id}/summary` | LLM estate summary for a tenant |
| `GET` | `/api/results/{tenant_id}/stream` | SSE stream of live scan results |
| `POST` | `/api/scan/global` | Start a global scan of all tenants |
| `GET` | `/api/scan/global/status` | Global scan state + phase timings |
| `GET` | `/api/scan/global/stream` | SSE stream of global scan progress |

### Analytics & Leaderboard

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/leaderboard?limit=100&min_devices=1` | Tenants ranked by worst CVE posture |
| `GET` | `/api/stats` | Estate-wide statistics, top CVEs, top platforms, severity breakdown |
| `GET` | `/api/ai/stats` | Live LLM back-fill worker metrics |

### Exports

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/export/all` | Excel workbook of all vulnerable devices across every tenant |
| `GET` | `/api/export/tenant/{tenant_id}` | Excel workbook for a single tenant |

The Excel export includes only devices with a CVE score > 0 and has the following columns: Client Name, Device Name, PON, Platform, Device Type, Current Firmware, NVD Min-Fix Version, Eng Recommended Version (GTT Engineering, only when the device is behind it), Serial Number, Device CVE Score (colour-coded), Number of Vulnerabilities.

### Health

| Method | Path | Description |
|---|---|---|
| `GET` | `/status` | Service health check |
| `GET` | `/api/gia/status?reload=false` | Cached GTT Engineering versions table, load state and match counters |

---

## Configuration

All configuration is via environment variables. The defaults below are suitable for local development only.

| Variable | Default | Description |
|---|---|---|
| `NETBOX_URL` | `http://localhost:8000` | Base URL of the NetBox instance |
| `NETBOX_TOKEN` | — | NetBox API token with read access to DCIM, Virtualization, and Tenancy |
| `VLLM_ENDPOINT` | — | Full URL of the vLLM `/v1/chat/completions` endpoint |
| `VLLM_MODEL` | `google/gemma-3-27b-it` | Model name to pass in the `model` field of chat completions requests |
| `VLLM_TOKEN` | `NONE` | Static bearer token (used when `LLM_AUTH_URL` is not set) |
| `LLM_AUTH_URL` | — | Keycloak token URL for client-credentials auth (overrides `VLLM_TOKEN`) |
| `LLM_CLIENT_ID` | — | Keycloak client ID |
| `LLM_CLIENT_SECRET` | — | Keycloak client secret |
| `REDIS_HOST` | `localhost` | Redis hostname |
| `REDIS_PORT` | `6379` | Redis port |
| `REDIS_DB` | `0` | Redis database index |
| `REDIS_PASSWORD` | `password` | Redis AUTH password |
| `CACHE_DIR` | `/app/cache` | Directory for SQLite DB and JSON caches |
| `GIA_API_URL` | `https://gia-ai.gt-t.net/api` | GIA API root shared by FBA (`/fba`) and SAM/DIU (`/sam/diu`); set this where GIA has a different name (e.g. production) |
| `FBA_BASE_URL` | `${GIA_API_URL}/fba` | Per-service override of the FBA endpoint |
| `GIA_DIU_URL` | `${GIA_API_URL}/sam/diu` | Per-service override of the DIU endpoint (engineering recommended versions) |
| `GIA_API_KEY` | `FBA_API_KEY` | `X-API-Key` for GIA; defaults to the FBA key |
| `GIA_VERIFY_SSL` | `FBA_VERIFY_SSL` | CA bundle path, `true` or `false`; defaults to the FBA setting |
| `GIA_CACHE_TTL_HOURS` | `24` | How long the engineering table is cached in memory |
| `GIA_RETRY_MINUTES` | `10` | Wait before retrying a failed table load |
| `GIA_PAGE_QUERY` | `SD-WAN Software Version Control` | Confluence page title searched via DIU |
| `GIA_SECTION_TEXT` | `Fortinet Edges, Gateways, and Central Management Devices` | Section text the search is restricted to |
| `GIA_TABLE_IDS` | `6848998_SEC_42_TABLE_1,6848998_SEC_42_TABLE_2` | Table ids fetched directly when the search finds no tables |
| `GIA_DEBUG` | `false` | Log every GIA request and device → row decision |

Redis is used only for scan progress counters. It is not required for core functionality — if Redis is unavailable the service logs a warning and continues.

---

## Running Locally

```bash
cd backend
pip install -r requirements.txt

# Minimum required env vars:
export NETBOX_URL=https://your-netbox-instance
export NETBOX_TOKEN=your_token_here
export VLLM_ENDPOINT=https://your-vllm/v1/chat/completions
export VLLM_TOKEN=your_token_here

uvicorn main:app --host 0.0.0.0 --port 5174 --reload
```

The service will be available at `http://localhost:5174`. The SQLite database and JSON caches are written to `/app/cache/` by default — set `CACHE_DIR` to a writable local path when running outside Docker (e.g. `export CACHE_DIR=./cache`).

---

## Docker

Build and run the backend container directly:

```bash
docker build -t halo-cve-backend ./backend
docker run -p 5174:5174 \
  -e NETBOX_URL=https://... \
  -e NETBOX_TOKEN=... \
  -e VLLM_ENDPOINT=https://... \
  -v cve_cache:/app/cache \
  halo-cve-backend
```

Or use the provided compose file to run the full stack (frontend + backend + Redis):

```bash
# Copy the compose file and fill in your credentials
docker compose -f docker-compose.cve.yaml up --build
```

The frontend is served on port 80. The backend API is reachable directly on port 5174 and through the nginx proxy at `http://localhost/api/`.
