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

## Development (split, without Docker)

```bash
# backend
cd backend && pip install -r requirements.txt && uvicorn main:app --port 5174
# frontend
cd frontend && npm install && npm run dev
```

In split mode the SPA falls back to `http://localhost:5174` for the API base.
