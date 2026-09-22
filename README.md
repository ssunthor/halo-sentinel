# Sentinel

Standalone Customer CVE Analyzer — a React dashboard ([frontend/](frontend)) over a
FastAPI backend ([backend/](backend)) that scans NetBox estates for CVEs and produces
AI risk write-ups, scheduled scans, and Excel/email reports.

This repo was consolidated from two previously separate repos (their full commit
histories are preserved under `frontend/` and `backend/`).

## Run it — single container

Everything (nginx-served SPA, the FastAPI backend, and a bundled Redis) runs in one
image, exposing a single port. nginx serves the built SPA and proxies `/api`,
`/status`, and the SSE endpoints to the backend on `127.0.0.1:5174`; the SPA calls the
API same-origin (`VITE_API_BASE_URL=""`).

```bash
docker compose up --build      # then open http://localhost:8080
```

or without compose:

```bash
docker build -t sentinel .
docker run -p 8080:80 -v sentinel-cache:/app/cache sentinel
```

Persistent state (the SQLite DB and JSON caches) lives in the `/app/cache` volume.
Redis holds only transient scan-progress state and needs no volume.

## Configuration

Runtime is env-var driven — NetBox URL/token, the vLLM endpoint (+ optional Keycloak
auth), scan schedule, and FBA settings. See the `os.getenv(...)` block near the top of
[backend/main.py](backend/main.py) for the full list, and `docker-compose.yaml` for the
ones you'll usually set.

## Version matching

Candidate CVEs come from NVD's free-text `keywordSearch` ("FortiOS 7.2.13"), which returns
any CVE whose text mentions those tokens — including ones where the version belongs to a
different product in the same advisory. Each candidate is then checked against NVD's
structured CPE ranges (`backend/cve_matching.py`): a CVE is dropped only when NVD lists a
vulnerable range for the device's own product and the device's version is outside every one
of them. A CVE with no CPE data, or none for that product, is kept. "NVD min fix" is derived
from the same product's ranges, preferring the device's release branch.

## Config-aware CVE applicability

A version match only says a device _might_ be vulnerable. When Sentinel has the device's
running configuration it goes further and gives every CVE a per-device verdict:

| Verdict | Meaning |
| --- | --- |
| `exploitable` | The vulnerable feature is enabled and reachable |
| `mitigated` | Enabled, but the config already restricts who can reach it |
| `not_applicable` | The vulnerable feature is not enabled on this device |
| `config_independent` | Exploitability does not depend on configuration — patch |
| `undetermined` | The config does not settle it; treat the CVE as applicable |

Each verdict carries the config lines that justify it (with real line numbers) and, where a
config workaround exists, a ready-to-paste suggested change. The device detail view shows
all three under each CVE.

How it stays trustworthy:

- **Secrets are redacted first.** Password hashes, PSKs, private keys and SNMP communities
  are stripped line-for-line before a config is stored, prompted or displayed. Only
  redacted text is ever persisted.
- **Evidence is cited by line number, never quoted.** The model returns line ranges;
  Sentinel slices the snippet out of the real config and rejects any range the model was
  not actually shown. A `mitigated` / `not_applicable` verdict without surviving evidence is
  downgraded to `undetermined`, so a hallucination can never hide a real vulnerability.
- **Verdicts are stamped with the config hash.** A changed config or a newly matched CVE
  re-queues just that work; results survive rescans.

Config sources:

- **FBA** — Fortinet configs are pulled automatically. FBA is only the config _source_; the
  verdicts are Sentinel's own analysis of the full config, not limited to the admin-ACL and
  password checks FBA performs.
- **Push** — any vendor. A Defense Halo instance sends the latest version from its config
  store to `PUT /api/device/{name}/config` with `Authorization: Bearer <CONFIG_PUSH_TOKEN>`
  (see `sentinel_push.py` in halo-backend). Push is disabled until `CONFIG_PUSH_TOKEN` is
  set. A pushed config is never overwritten by FBA's copy.

Two things follow from the verdicts:

- **Effective score.** Each device (and tenant roll-up) carries an
  `effective_severity_score`: the highest CVSS among CVEs the device's current config has
  _not_ ruled out (`not_applicable` / `mitigated`). Raw CVSS is never changed — both are
  shown, and `GET /api/leaderboard?score=effective` ranks by the config-aware one. A changed
  config invalidates its verdicts, so the effective score falls back to raw until re-analysed.
- **The prose AI Analysis agrees with them.** The per-device write-up is given the verdicts
  as established facts, its cache key includes a verdict fingerprint, and it is regenerated
  whenever the verdicts change — so it never calls a ruled-out CVE "critical".

Code: [backend/config_sections.py](backend/config_sections.py) (redaction, section parsing
for FortiOS / Cisco-style / Junos), [backend/cve_applicability.py](backend/cve_applicability.py)
(LLM stages and evidence validation), [backend/config_applicability.py](backend/config_applicability.py)
(worker, API, env vars). Tests: `cd backend && python3 -m pytest tests -q` (no network or LLM
needed).

## FBA connectivity

FBA's TLS certificate is issued by the corporate CA (`GICORP-ROOT-CA01`), which is not in
the default CA bundle the backend's HTTP client uses. Without it every FBA request fails
certificate verification and no device gets config data. Set `FBA_VERIFY_SSL` to the path
of a CA bundle containing that root (preferred — mount it into the container), or to
`false` to skip verification.

FBA enrichment does not look devices up one at a time. Every `FBA_SYNC_MINUTES` (default 60)
it pulls FBA's complete inventory listing (about 11 requests for ~10k configs), matches every
Fortinet device locally (exact filename, else recognised HA-node suffixes such as `-A`/`-B`),
and fetches the full audit only for devices whose FBA `last_analyzed_at` changed since it was
stored. Devices absent from the listing are recorded as not in FBA at no cost. Non-Fortinet
devices are never considered. All requests share one rate limiter, `FBA_RATE_LIMIT` requests
per second (default 5).

To see what is happening on the FBA (GIA) API: `FBA_DEBUG=true` logs every request with its
status or exception and latency, the enrichment worker's progress line reports found / not in
FBA / failed counts plus the last error, and `GET /api/config-applicability/status` exposes
`fba_requests` (live request counters) and `fba_run` (the current enrichment run). When every
lookup in a batch fails the run aborts immediately with the reason instead of grinding through
the whole estate.

A lookup that _fails_ (TLS, timeout, 5xx) is kept separate from one where FBA answers "no
such device": failures are logged, never overwrite existing data, and are retried after
`FBA_RETRY_HOURS` (default 1) rather than being cached as "not found". FBA data is carried across rescans, and the device view distinguishes
_not checked yet_, _lookup failed_, _not in FBA_ and _in FBA but not audited_.

## Development (split, without Docker)

```bash
# backend
cd backend && pip install -r requirements.txt && uvicorn main:app --port 5174
# frontend
cd frontend && npm install && npm run dev
```

In split mode the SPA falls back to `http://localhost:5174` for the API base.
