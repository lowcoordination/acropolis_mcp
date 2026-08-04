# Quickstart

Acropolis is a self-hostable gateway for [MCP](https://modelcontextprotocol.io) servers. It sits
between your MCP clients (Claude, an agent, whatever you're pointing at your tools) and your
actual MCP servers, and gives you a web UI to control which tools each client can use, watch
every call as it happens, and rate-limit or block the ones you don't trust.

This guide gets you from nothing to a locked-down MCP server in about five minutes.

## Prerequisites

- Docker and Docker Compose
- At least one MCP server you want to put behind Acropolis (any server speaking the
  [Streamable HTTP transport](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports))

## 1. Start Acropolis

```bash
git clone https://github.com/lowcoordination/acropolis_mcp.git
cd acropolis_mcp
docker compose -f deploy/docker-compose.yml up
```

The first run builds the image (a minute or two); after that, startup is a few seconds.
Once you see `Uvicorn running on http://0.0.0.0:8000`, open **http://localhost:8000**.

> Running this on a machine other than your own laptop, or somewhere reachable beyond
> `localhost`? Read [TLS and reverse proxy setup](tls-and-reverse-proxy.md) first — by
> default Acropolis serves plain HTTP, and you don't want API keys or your admin session
> traveling in the clear.

## 2. Finish setup

The first time you open Acropolis, you'll land on a setup wizard. It asks for:

- **An admin password** — this protects the control plane (the UI and its API). Pick
  something real; there's no recovery flow yet beyond resetting the data volume.
- **Data-plane authentication mode**:
  - **Keyed** (recommended, the default) — every request to `/mcp/*` needs a valid API key.
  - **Open** — no key required. Only reasonable if Acropolis and every client are on a network
    you fully trust, and even then, keyed is usually just as easy.

Submit the form and you're in — the dashboard, empty for now, is your home page from here on.

## 3. Register your first server

Go to **Servers → Add server**. You need:

- **Name** — anything human-readable.
- **Slug** — auto-filled from the name; this becomes part of the URL clients will use
  (`/mcp/<slug>`).
- **Upstream URL** — the full URL of your MCP server's Streamable HTTP endpoint, e.g.
  `http://localhost:8010/mcp`. If your MCP server runs in another Docker container, use that
  container's name or a reachable host, not `localhost` — Acropolis is asking itself, not you.

Submit, and Acropolis immediately reaches out to your server to confirm it can see it — you'll
land on the servers list with a **healthy** badge and a protocol badge (most servers today say
`2025-06-18`) already showing, no waiting. If a server goes offline or you change its URL
later, hit **Re-probe** on its detail page to check again on demand.

## 4. Look at what it can actually do

Click into the server you just added. You'll see every tool it exposes, pulled live from the
server itself — not a config file you have to keep in sync by hand.

By default, every server starts in **passthrough** mode: nothing is blocked, every call is
just logged. That's a reasonable starting point while you figure out what you actually want
to restrict.

## 5. Lock something down

Say your server has a tool you don't want a particular client calling — a shell-execution
tool, a delete-anything tool, whatever it is.

1. Change **Mode** to **Allowlist** (only listed tools pass) or **Denylist** (everything
   passes except what you list) — whichever is less typing for your case.
2. Toggle the tool you want to restrict.
3. Click **Save policy**.

That's it — the change takes effect immediately, no restart. If you're on Allowlist mode and
just denied everything by switching modes, remember to toggle back on the tools you *do*
want to keep working before you save.

## 6. Watch it work

Go to **Audit**. If you have a real MCP client pointed at Acropolis, drive some traffic through
it — an allowed call and a call to the tool you just locked down. You'll see both land in the
**live tail** in real time: decision (`ALLOWED` / `BLOCKED`), which rule fired, and (for
blocked calls) exactly why.

## 7. Point a real client at it

If you were talking to your MCP server directly before, the only change a client needs is the
URL: swap `http://<your-server>:<port>/mcp` for `http://<acropolis-host>:8000/mcp/<slug>` (the
slug from step 3). If `auth_mode` is **keyed**, also add the API key you create on the **API
Keys** page as a bearer token — `Authorization: Bearer acropolis_...`.

There's also an **aggregate endpoint** at `/mcp` (no slug) that merges every server you've
marked "include in aggregate" into one connection, with tools namespaced as
`<slug>__<tool_name>` — useful if your client only wants to manage one MCP connection instead
of one per server.

## What's next

- [Policy cookbook](policy-cookbook.md) — allowlist/denylist patterns for common server types,
  and how to write a parameter rule (block a regex, cap a value, deny a param outright).
- [Protocol bridging notes](protocol-bridging.md) — what Acropolis does when an old-generation
  MCP server talks to a new-generation client, and what's intentionally not supported yet.
- [TLS and reverse proxy setup](tls-and-reverse-proxy.md) — do this before exposing Acropolis
  beyond your own machine.
