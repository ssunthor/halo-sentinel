# syntax=docker/dockerfile:1

# ---- Stage 1: build the React SPA ----
# Base images pinned by digest for reproducibility and the CI annotation check.
FROM node:20-alpine@sha256:fb4cd12c85ee03686f6af5362a0b0d56d50c58a04632e6c0fb8363f609372293 AS frontend
WORKDIR /app
COPY frontend/package.json ./
# lockfile is known to drift; install (not ci) regenerates the tree
RUN npm install --legacy-peer-deps
COPY frontend/ ./
RUN npm run build            # -> /app/dist

# ---- Stage 2: single runtime image (nginx + uvicorn + redis via supervisor) ----
FROM python:3.11-slim@sha256:db3ff2e1800a8581e2c48a27c3995339d47bdf046da21c7627accd3d51053a93
ENV PYTHONUNBUFFERED=1 \
    CACHE_DIR=/app/cache \
    REDIS_HOST=127.0.0.1 \
    REDIS_PORT=6379 \
    REDIS_PASSWORD=""

RUN apt-get update \
    && apt-get install -y --no-install-recommends nginx supervisor redis-server \
    && rm -rf /var/lib/apt/lists/* \
    && rm -f /etc/nginx/sites-enabled/default

# Python deps
WORKDIR /app/backend
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Backend source (.mmdb geoip files are excluded via .dockerignore — unused)
COPY backend/ /app/backend/

# Built SPA + same-origin env shim
COPY --from=frontend /app/dist /usr/share/nginx/html
COPY docker/env-config.js /usr/share/nginx/html/env-config.js

# Process + proxy config
COPY docker/nginx.conf /etc/nginx/conf.d/default.conf
COPY docker/supervisord.conf /etc/supervisord.conf

RUN mkdir -p /app/cache
VOLUME ["/app/cache"]

EXPOSE 80
CMD ["supervisord", "-c", "/etc/supervisord.conf"]
