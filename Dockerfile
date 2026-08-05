# Digest-pinned so a rebuild is reproducible and doesn't silently pick up an upstream tag move;
# `apt-get upgrade` below is the actual mechanism for picking up OS-level security patches —
# re-run the build periodically rather than relying on the tag floating.
FROM node:22-slim@sha256:d649c27dae7ba0137b3cef5dd75baa422c08dc3d9e3fc0c23dfb172dc3cc6436 AS web-build

WORKDIR /web

COPY web/package.json web/package-lock.json ./
RUN npm ci

COPY web/ ./
RUN npm run build

FROM python:3.12-slim@sha256:646fb0bca3dd3ea1bcc6feb72c17ed16eed6e10cffc732fcc1478bd3e7f02d7b

WORKDIR /app

RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*

RUN useradd -m -u 1000 acropolis

COPY pyproject.toml requirements-lock.txt ./
COPY argus/ ./argus/
COPY archon/ ./archon/
COPY stoa/ ./stoa/
COPY db/ ./db/

# Install pinned deps first (reproducible builds — see requirements-lock.txt's own header for
# why this isn't hash-locked), then the project itself with --no-deps so pip doesn't re-resolve
# anything against pyproject.toml's looser ranges.
RUN pip install --no-cache-dir -r requirements-lock.txt && \
    pip install --no-cache-dir --no-deps .

COPY --from=web-build /web/dist ./web/dist

RUN mkdir -p /data && chown acropolis:acropolis /data

USER acropolis

ENV ACROPOLIS_DATA_DIR=/data
ENV ACROPOLIS_HOST=0.0.0.0
ENV ACROPOLIS_PORT=8000

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/v1/health')"

CMD ["python", "-m", "argus"]
