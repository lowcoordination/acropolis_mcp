FROM python:3.12-slim

WORKDIR /app

RUN useradd -m -u 1000 argus

COPY pyproject.toml .
COPY argus/ ./argus/
COPY archon/ ./archon/
COPY stoa/ ./stoa/
COPY db/ ./db/

RUN pip install --no-cache-dir .

RUN mkdir -p /data && chown argus:argus /data

USER argus

ENV ARGUS_DATA_DIR=/data
ENV ARGUS_HOST=0.0.0.0
ENV ARGUS_PORT=8000

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/v1/health')"

CMD ["python", "-m", "argus"]
