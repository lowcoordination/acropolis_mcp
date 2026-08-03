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

Pre-1.0. The gateway, policy engine, and web UI are functional and covered by an extensive
integration test suite (real MCP servers in every test, nothing mocked), but this hasn't yet
seen production traffic beyond its own development. Expect rough edges; please open an issue
if you hit one.

## Quickstart

```bash
docker compose -f deploy/docker-compose.yml up
```

Then open `http://localhost:8000` to finish setup — see [docs/quickstart.md](docs/quickstart.md)
for the full walkthrough (registering a server, locking down a tool, watching the audit log).

Exposing Argus beyond your own machine? Read
[docs/tls-and-reverse-proxy.md](docs/tls-and-reverse-proxy.md) first.

## Development

```bash
pip install -e ".[dev]"
python -m argus
```

Run tests:

```bash
pytest
```
