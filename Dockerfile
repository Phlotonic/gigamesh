# GigaMesh Production Multi-Stage Dockerfile (Control Plane + Frontend + Winning Rust Edge Binary)
# Copyright (C) 2026 Adam Dryden and Quanumis Systems.

# Stage 1: Build Novice-First + Expert React PWA Frontend
FROM node:22-alpine AS frontend-builder
WORKDIR /build/frontend
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# Stage 2: Build Winning Rust `gigamesh-edge` Binary (356 KB stripped, GC-free)
FROM rust:1.85-slim AS edge-builder
WORKDIR /build/edge/rust
COPY edge/rust/ ./
RUN cargo build --release

# Stage 3: Hardened Non-Root Python Control Plane Runtime
FROM python:3.12-slim
LABEL org.opencontainers.image.title="GigaMesh" \
      org.opencontainers.image.description="Self-Evolving Agentic & Industrial OT SIEM (Adam Dryden & Quanumis Systems)" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later"

RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -u 10001 gigamesh

WORKDIR /app
COPY backend/pyproject.toml /app/backend/pyproject.toml
COPY backend/gigamesh /app/backend/gigamesh
RUN pip install --no-cache-dir /app/backend

COPY --from=frontend-builder /build/frontend/dist /app/frontend/dist
COPY --from=edge-builder /build/edge/rust/target/release/gigamesh-edge-rust /usr/local/bin/gigamesh-edge
COPY .mcp.json /app/.mcp.json
COPY LICENSE NOTICE COMMERCIAL_LICENSE.md /app/

RUN mkdir -p /app/data /app/genome_repo && chown -R gigamesh:gigamesh /app
USER gigamesh

ENV PYTHONPATH=/app/backend \
    GIGAMESH_BASE_DIR=/app
EXPOSE 8000

HEALTHCHECK --interval=20s --timeout=5s --retries=3 \
  CMD python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/readyz', timeout=3)"

CMD ["uvicorn", "gigamesh.api.server:app", "--host", "0.0.0.0", "--port", "8000"]
