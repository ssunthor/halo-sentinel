# Defense Halo — Customer CVE Analyzer (Frontend)

React + Vite single-page application that provides a real-time vulnerability management dashboard for the Defense Halo Customer CVE Analyzer platform. It connects to the FastAPI backend over REST and Server-Sent Events (SSE) to show live scan progress, per-device CVE data, AI-generated security assessments, and estate-wide analytics.

---

## Table of Contents

1. [Overview](#overview)
2. [Tech Stack](#tech-stack)
3. [Application Flow](#application-flow)
4. [Pages and Components](#pages-and-components)
   - [Leaderboard (Landing Page)](#leaderboard-landing-page)
   - [Tenant View](#tenant-view)
   - [Global Scan Panel](#global-scan-panel)
   - [AI Analysis Engine Panel](#ai-analysis-engine-panel)
   - [Tenant Selector](#tenant-selector)
5. [SSE Streaming](#sse-streaming)
6. [Configuration](#configuration)
7. [nginx Routing](#nginx-routing)
8. [Running Locally](#running-locally)
9. [Docker](#docker)

---

## Overview

The frontend is a dark-themed, monospace-style SPA built for security operations teams. Its primary views are:

- A **Leaderboard landing page** that shows estate-wide statistics, customer risk rankings, top CVEs, platform exposure, severity distribution, and live AI worker metrics — all loaded on first visit with no tenant selection required.
- A **Tenant detail view** that streams live vulnerability scan results for a selected customer, shows per-device CVE scores and AI-generated analysis, and displays an LLM-generated estate risk assessment.
- A **Global Scan panel** in the navigation bar that lets operators trigger a full estate-wide scan and monitor its progress in real time.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Framework | React 18 (functional components + hooks) |
| Build tool | Vite |
| Styling | Tailwind CSS |
| Icons | Lucide React |
| Markdown rendering | `react-markdown` + `remark-gfm` (for LLM analysis output) |
| Web server (production) | nginx (serves static build, proxies `/api/` to backend) |

---

## Application Flow

```
Browser loads index.html (served by nginx)
        │
        ▼
App.jsx — owns global state (selectedTenant)
        │
        ├─── No tenant selected ──► Leaderboard.jsx
        │                           │  polls /api/stats + /api/leaderboard
        │                           │  polls /api/ai/stats every 5s
        │                           │  clicking a row → setSelectedTenant()
        │
        └─── Tenant selected ─────► NetboxVulnerabilities.jsx
                                    │
                                    ├─ POST /api/scan/{id}  (trigger scan)
                                    │
                                    ├─ GET  /api/results/{id}/stream  (SSE)
                                    │        device events arrive in real time
                                    │
                                    ├─ polls /api/results/{id}/summary every 5s
                                    │        until LLM estate summary appears
                                    │
                                    └─ GET  /api/export/tenant/{id}  (xlsx download)
```

The navigation bar is always visible and contains:
- The **Global Scan Panel** (triggers and monitors a full estate scan)
- The **Tenant Selector** (debounced search against the NetBox API)

---

## Pages and Components

### Leaderboard (Landing Page)

**Component:** `src/components/Leaderboard.jsx`

The default view shown when no tenant is selected. It fetches data from two endpoints in parallel on mount and refreshes every 60 seconds:
- `GET /api/stats` — estate-wide aggregates
- `GET /api/leaderboard?limit=500` — per-tenant ranking rows

**Sections:**

#### Estate Stat Cards
Six summary cards across the top showing:
- Total clients scanned, total devices, vulnerable devices (with % of estate), critical devices (CVE score ≥ 9.0), total CVE instances, and peak CVE score.

#### Info Panels (4-column grid on wide screens)

| Panel | Data source | What it shows |
|---|---|---|
| Severity Breakdown | `stats.severity_breakdown` | Proportional bar chart of CVE count by severity (CRITICAL / HIGH / MEDIUM / LOW / UNKNOWN) |
| Top Platforms | `stats.top_platforms` | OS platforms ranked by vulnerable device count, with per-platform vulnerability percentage bar |
| Most Widespread CVEs | `stats.top_cves` | Top 8 CVEs by device count across the entire estate, with NVD links |
| AI Analysis Engine | `GET /api/ai/stats` (every 5s) | Live LLM worker status, queue depth, session totals, latency stats, cache hit rate |

#### Customer Rankings Table
A sortable, filterable table of all scanned tenants ordered by CVE score descending by default. Columns:

| Column | Notes |
|---|---|
| Rank | Gold/silver/bronze medal for top 3 |
| Client | Clickable — selects tenant and navigates to detail view |
| Devices | Total device + VM count |
| Vulnerable | Count with orange highlight if > 0 |
| Vuln% | Percentage with mini progress bar |
| CVE Score | Colour-coded: red ≥ 9, orange ≥ 7, yellow ≥ 4 |
| Risk | LLM risk posture badge (Critical / High / Medium / Low / Clean) |
| Trend | Arrow icon from LLM trend assessment (improving / declining / stable) |
| Last Scan | Relative time |

The table supports client-side text filtering and can be sorted on any column by clicking the header.

**Export All button** — triggers `GET /api/export/all` which downloads an Excel workbook containing all vulnerable devices across every scanned tenant.

---

### Tenant View

**Component:** `src/components/NetboxVulnerabilities.jsx`

Loaded when a tenant is selected. The component:

1. **Triggers a scan** — `POST /api/scan/{tenantId}?tenant_name=...` on mount. If the backend returns `status: cached` the component loads results directly from `GET /api/results/{id}`. If `status: refreshing`, it loads stale results immediately and simultaneously opens an SSE stream for updates. If `status: started`, it opens an SSE stream and waits for data.

2. **Streams results via SSE** — `GET /api/results/{id}/stream` emits `{"type": "device", "data": {...}}` events as each device is scanned. The component merges these into a local `devicesRef` map keyed by `resource_name` and sorts by score descending on every update. The device list therefore builds up progressively with the most critical devices appearing first.

3. **Polls for estate summary** — After the SSE stream signals `complete`, the component polls `GET /api/results/{id}/summary` every 5 seconds until an LLM-generated summary appears (LLM generation can take 30+ seconds for large tenants).

4. **Manual rescan** — A "Rescan" button calls `POST /api/scan/{id}?force=true` to bypass the 24-hour cache and start a fresh scan immediately.

5. **Export** — An "Export .xlsx" button (visible once results are loaded) calls `GET /api/export/tenant/{id}` to download an Excel workbook for the tenant.

#### Estate Summary Panel (`EstateSummaryPanel`)
Shown above the device list when the LLM summary is available. Displays:
- Risk posture badge with border/background colour matching severity
- One-sentence risk summary
- Three stat boxes: total scanned, vulnerable count, max CVE score
- Top CVEs across the estate with NVD links, scores, and recommended actions
- Prioritised remediation recommendations (numbered list)
- Trend comparison vs previous scan

#### Device List
Each row shows: category icon, device name, model/cluster, OS string, and CVSS score. Colour-coded left border: green = clean, yellow = low, orange = medium/high, red = critical.

Clicking a row opens a **Device Detail Modal** with:
- Full CVE list: each entry links to the NVD detail page and shows score, severity, and description
- AI Analysis section: the LLM-generated device-specific security assessment, rendered as Markdown

**Filters:** text search (name, model, OS), page size selector (10 / 25 / 100 / All), toggles for "Unknown" devices (score = 0) and "Virtual Machines".

---

### Global Scan Panel

**Component:** Defined inline in `src/App.jsx` as `GlobalScanPanel`.

A button in the nav bar that toggles a dropdown panel. Clicking "Scan All Tenants" calls `POST /api/scan/global` and immediately opens an SSE connection to `GET /api/scan/global/stream` to receive live progress events.

The panel is always clickable (even while a scan is running) so operators can check progress at any time. It auto-opens when a scan is detected as running (e.g. after a page refresh).

**Progress sections:**

| Section | Metrics shown |
|---|---|
| Inventory | Total devices, physical count, VM count |
| Platform Analysis | Distinct OS platforms, unique version combos (= NVD queries), devices without platform data |
| NVD Queries | Completed, waiting, cache hits; progress bar |
| Results | Devices with CVEs found; tenants saved (X of Y) |
| Timing | Elapsed, inventory phase, NVD phase, save phase |

A "Run Again" button appears after completion to trigger a fresh scan.

---

### AI Analysis Engine Panel

**Component:** `AiStatsPanel` in `src/components/Leaderboard.jsx`

Shown on the leaderboard landing page. Polls `GET /api/ai/stats` every 5 seconds. Displays live metrics from the backend's LLM back-fill worker:

| Metric | Description |
|---|---|
| Status indicator | Pulsing green dot = actively analyzing, gray = idle, yellow = starting up |
| Current job | Device name and tenant being analyzed right now |
| Analyzed (24h) | Devices the worker has completed in the last 24 hours |
| In queue | Total vulnerable devices still awaiting analysis |
| Tenants pending | How many tenants still need work |
| Session total | Devices analyzed since the service last restarted |
| API calls / Cache hits | Breakdown of real vLLM calls vs cache hits |
| Avg / P95 / Min / Max latency | Rolling stats over the last 100 real API calls |
| Cache hit rate bar | Visual percentage showing how effectively the LLM cache is working |

---

### Tenant Selector

**Component:** Defined inline in `src/App.jsx` as `TenantSelector`.

A searchable dropdown in the nav bar. Typing triggers a debounced (300ms) request to `GET /api/tenants/search?q=...`. When the dropdown opens without a search query, it loads `GET /api/tenants/recent` to show previously scanned tenants sorted by most recently scanned.

Features:
- **"Has devices" toggle** — filters NetBox results to tenants that have at least one device or VM (performs a quick count check per tenant against NetBox)
- Shows device count and scan age for tenants with cached data
- Stale indicator (yellow clock icon) when cache is ≥ 24 hours old
- Selecting a tenant navigates to the Tenant View and clears the search field

---

## SSE Streaming

Two SSE endpoints are used:

### `GET /api/results/{tenant_id}/stream`
Used by the Tenant View. If a scan is active, emits device update events as they arrive from the scan worker. If no scan is active, flushes the full cached result set immediately and closes.

Event format:
```json
{"type": "device", "data": {"resource_name": "...", "os": "...", "highest_severity_score": 9.1, "cves": [...], "llm_analysis": "..."}}
{"type": "complete"}
```

### `GET /api/scan/global/stream`
Used by the Global Scan Panel. Emits progress snapshots throughout the scan and a final `complete` event.

Event format:
```json
{"type": "progress", "state": {"status": "running", "devices_fetched": 50000, "nvd_queried": 420, ...}}
{"type": "complete", "state": {...}}
```

The nginx configuration disables proxy buffering for both SSE endpoints (`proxy_buffering off`) to ensure events are flushed to the browser immediately as they arrive from the backend.

---

## Configuration

Runtime configuration is injected into `window._env_` by the nginx container's `entrypoint.sh` at startup, so the built JavaScript bundle does not need to be rebuilt when switching environments.

| Variable | Default | Description |
|---|---|---|
| `VITE_API_BASE_URL` | `http://localhost:5174` | Base URL for API calls (no trailing slash, no `/api` suffix) |
| `BACKEND_URL` | `backend:5174` | nginx upstream target (Docker internal hostname:port) |

In the Docker Compose stack, `VITE_API_BASE_URL=http://localhost` (port 80, served by nginx) and `BACKEND_URL=backend:5174` (Docker network internal).

When running the Vite dev server locally, set `VITE_API_BASE_URL=http://localhost:5174` in a `.env.local` file to point directly at the backend.

---

## nginx Routing

The production container runs nginx and serves the Vite build from `/usr/share/nginx/html`. API calls are proxied to the backend:

| Path | Behaviour |
|---|---|
| `/` and all SPA routes | Served from `index.html` (React Router fallback) |
| `/api/scan/global/stream` | Proxied to backend, `proxy_buffering off`, 1-hour read timeout |
| `/api/results/*/stream` | Proxied to backend, `proxy_buffering off`, 1-hour read timeout |
| `/api/*` | Proxied to backend, 5-minute read timeout |
| `/status` | Proxied to backend health check |

SSE endpoints get dedicated location blocks with buffering disabled because nginx's default behaviour buffers the response body before forwarding it, which would delay all events until the stream closes.

---

## Running Locally

```bash
cd dashboard/frontend
npm install

# Point at the backend
echo "VITE_API_BASE_URL=http://localhost:5174" > .env.local

npm run dev
```

The dev server starts at `http://localhost:5173` with hot module replacement enabled.

To build for production:
```bash
npm run build        # outputs to dist/
npm run preview      # preview the production build locally
```

---

## Docker

The frontend image is a two-stage build:
1. **Build stage:** `node:alpine` — runs `npm ci && npm run build`
2. **Serve stage:** `nginx:alpine` — copies the `dist/` output and the `nginx/default.conf` configuration

`entrypoint.sh` runs before nginx starts and injects runtime environment variables into `env-config.js` so the SPA can read them from `window._env_` without a rebuild.

Build and run:
```bash
docker build -t halo-cve-frontend ./dashboard/frontend
docker run -p 80:80 \
  -e BACKEND_URL=host.docker.internal:5174 \
  -e VITE_API_BASE_URL=http://localhost \
  halo-cve-frontend
```

Or use the full compose stack:
```bash
docker compose -f docker-compose.cve.yaml up --build
```

The application is served at `http://localhost` (port 80).
