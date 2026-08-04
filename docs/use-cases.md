# Use cases

This page walks through the situations Acropolis is built for, with what you'd actually
configure for each. If you haven't run it yet, start with the [quickstart](quickstart.md) —
this page assumes you know the shape of the product (servers, policies, API keys, audit log)
and is about *why* and *when*, not *how*.

## 1. Restricting what an AI agent or assistant can do on an MCP server

**The problem:** you want to give an LLM-based client (Claude, an agent framework, an
internal tool) access to an MCP server, but not unrestricted access. A filesystem server
that can read config files shouldn't also be able to write them. A server with a
shell-execution tool is a liability if every client that can reach it can call that tool.

**How Acropolis addresses it:** register the server once, then set a per-server policy —
allowlist (only listed tools pass) or denylist (everything passes except what you list) —
and, where tool-level granularity isn't enough, a parameter rule (block a regex pattern, cap
a value, deny a parameter outright, whatever the API key's client sends never reaches the
upstream unless it satisfies every rule you've defined). The result is enforced on every
call, not just documented as a convention the client is expected to follow — a compromised
or misbehaving client can't reach a tool it wasn't granted, regardless of what it asks for.

## 2. Presenting many MCP servers as one connection

**The problem:** you run several MCP servers (a filesystem tool, a search tool, an internal
API wrapper, whatever your stack accumulates), and configuring every client to know about
every server individually doesn't scale — especially for clients that expect a single MCP
endpoint rather than a list of them.

**How Acropolis addresses it:** the aggregate endpoint (`/mcp`, no slug) merges every server
marked "include in aggregate" into one connection. Tools are namespaced (`<slug>__<tool>`) so
there's no collision between two servers that both happen to expose a tool called `search`.
Policy is enforced identically on the aggregate path — a tool denied on its per-server policy
is invisible in the aggregate's `tools/list` too, not just blocked when called. Add a new
server to your fleet, mark it for aggregation, and every client already pointed at the
aggregate endpoint sees its tools immediately, with no client-side reconfiguration.

## 3. Bridging old and new MCP protocol generations

**The problem:** the MCP spec changed meaningfully between 2025-06-18 (stateful, session-based)
and 2026-07-28 (stateless, header-routed). Most MCP servers in the wild today speak the older
generation. As clients and SDKs adopt the new spec, you end up needing new-generation clients
to talk to old-generation servers — and that translation isn't something either side does for
you.

**How Acropolis addresses it:** this is the core of the data-plane module (Argus). Register a
2025-generation server as normal; when a 2026-generation client connects, Acropolis
transparently maintains the session/handshake the old server expects, translates the
stateless request into the shape the upstream understands, and returns a plain JSON response
even though the upstream replied over SSE. A 2026 client never needs to know the upstream is
running an older implementation, and a 2025-generation client continues to work exactly as it
always has — unbridged, straight passthrough. See
[protocol bridging notes](protocol-bridging.md) for exactly what's translated and what's
explicitly out of scope.

## 4. Auditing and accountability for tool calls

**The problem:** once an MCP server is reachable by an automated client, "what did it
actually do" becomes a real question — for debugging (why did this call fail), for security
review (did anything try something it shouldn't have), or simply because more than one person
or system has a key and you want to know which one made a given call.

**How Acropolis addresses it:** every call — allowed, blocked, or errored — is written to the
audit log with a timestamp, the tool invoked, the decision, the specific rule that fired (for
blocks), the arguments passed (truncated to avoid logging secrets in full), and which API key
made the call. The Audit page in the UI offers a live tail (an actual open SSE stream, not
polling) alongside historical search and filtering by server or decision. A configurable
retention window (default 30 days, adjustable from Settings, or disabled for "keep forever")
prunes old entries on a background schedule so the log doesn't grow unbounded.

## 5. Giving different clients different levels of access

**The problem:** not every consumer of your MCP fleet should have the same reach. A
trusted internal automation might need broad access; a client you're handing to someone else,
or a lower-trust integration, should be limited to exactly the servers it needs.

**How Acropolis addresses it:** API keys are scoped per-server at creation time — a key can be
granted access to every registered server, or restricted to a specific subset. Each key is
shown in plaintext exactly once at creation and stored as a SHA-256 hash from then on, so
losing the database doesn't leak usable credentials. Revoking a key (or disabling it without
deleting it, if you want the audit history to remain attributable) takes effect immediately,
with no restart.

## 6. Running this yourself, without operating a fleet of proxies

**The problem:** if you're the kind of team or individual self-hosting MCP servers at all,
you're probably not looking to take on a second piece of infrastructure that needs its own
database cluster, its own scaling story, and its own on-call burden just to gate access to a
handful of tool servers.

**How Acropolis addresses it:** single process, SQLite for state (config and audit log both),
one Docker image, no external dependencies. A `docker compose up` gets you a running instance;
generic Kubernetes manifests are provided for anyone who wants it alongside existing cluster
workloads, with no cloud-provider-specific assumptions baked in. It's explicitly a
single-replica design — the [Kubernetes README](../deploy/k8s/README.md#why-only-one-replica)
explains why, and what "outgrowing this" would actually mean.

## What Acropolis is *not* for

Worth being direct about the edges of this, rather than letting the use cases above imply more
than what's actually built:

- **Not a multi-tenant SaaS control plane.** There's one admin identity per instance; no
  per-user accounts or role-based access beyond the admin/API-key split. If you need that,
  it's not there yet.
- **Not a general API gateway.** It speaks MCP specifically (Streamable HTTP transport, both
  spec generations) — it isn't a reverse proxy for arbitrary REST or gRPC traffic.
- **Not a replacement for TLS.** Acropolis doesn't terminate TLS itself; see
  [TLS and reverse proxy setup](tls-and-reverse-proxy.md) for the (required, if you're exposing
  it beyond localhost) piece that sits in front of it.
