FROM node:22-slim AS web-build

WORKDIR /web

COPY web/package.json web/package-lock.json ./
RUN npm ci

COPY web/ ./
RUN npm run build

FROM python:3.12-slim

WORKDIR /app

RUN useradd -m -u 1000 acropolis

COPY pyproject.toml .
COPY argus/ ./argus/
COPY archon/ ./archon/
COPY stoa/ ./stoa/
COPY db/ ./db/

RUN pip install --no-cache-dir .

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
