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

Code: [backend/config_sections.py](backend/config_sections.py) (redaction, section parsing
for FortiOS / Cisco-style / Junos), [backend/cve_applicability.py](backend/cve_applicability.py)
(LLM stages and evidence validation), [backend/config_applicability.py](backend/config_applicability.py)
(worker, API, env vars). Tests: `cd backend && python3 -m pytest tests -q` (no network or LLM
needed).

## Development (split, without Docker)

```bash
# backend
cd backend && pip install -r requirements.txt && uvicorn main:app --port 5174
# frontend
cd frontend && npm install && npm run dev
```

In split mode the SPA falls back to `http://localhost:5174` for the API base.
