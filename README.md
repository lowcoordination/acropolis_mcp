# Argus

A self-hostable gateway, policy engine, and registration hub for [MCP](https://modelcontextprotocol.io) servers.

Three modules, one process:

- **Argus** — the data plane. Routes `tools/call` and friends to your upstream MCP servers, enforces
  per-server and per-tool policy (allow/deny lists, parameter rules, rate limits), bridges between
  MCP protocol generations, and captures an audit trail of every decision.
- **Archon** — the control plane. A REST API and web UI for managing servers, policies, API keys,
  and reviewing the audit log.
- **Stoa** — the registration hub. Keeps an inventory of your MCP servers, polls their health and
  capabilities, and caches their tool catalogs.

## Status

Early development (M1: core data plane + minimal control API). Not yet ready for production use.

## Quickstart

```bash
docker compose -f deploy/docker-compose.yml up
```

Then open `http://localhost:8000` to finish setup.

## Development

```bash
pip install -e ".[dev]"
python -m argus
```

Run tests:

```bash
pytest
```
