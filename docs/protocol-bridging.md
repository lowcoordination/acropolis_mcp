# Protocol bridging

MCP has two generations of the spec in the wild right now, and Acropolis talks to both without
you having to think about which one your upstream servers or clients speak.

## The two generations

**2025-06-18** — the generation almost every MCP server today implements. Stateful: a client
sends `initialize`, the server may issue a session id (`Mcp-Session-Id`), and every subsequent
request on that connection carries it. Responses to POST requests come back as
`text/event-stream`, even for a single request/response exchange.

**2026-07-28** — the current spec, finalized recently. Stateless: no `initialize` handshake,
no session id. Every request carries its own protocol version and client info; every response
is a single, complete JSON object. Two new headers, `Mcp-Method` and `Mcp-Name`, are required
on every request specifically so a gateway (like Acropolis) can route and enforce policy without
parsing the JSON-RPC body first.

Realistically, almost every MCP server you point Acropolis at today is 2025-06-18. 2026-07-28
clients will show up over time as SDKs and agent frameworks catch up to the new spec. Acropolis is
built to make that transition invisible: register your (2025-generation) server once, and it
works correctly whether the client talking to it is old or new.

## How Acropolis tells them apart

Acropolis looks for the `Mcp-Method` header. If it's present, the request is treated as
2026-generation and stateless. If it's absent, the request is treated as 2025-generation —
which means it should be part of a session that started with a real `initialize` call.

There's no ambiguity in practice: a 2025-generation client never sends `Mcp-Method` (the
header didn't exist yet when it was written), and a 2026-generation client is required by
spec to send it on every request.

## What happens on each path

**2025 client → 2025 upstream (today's default case):** Acropolis passes the request through
unchanged — the same `initialize`/session/SSE dance the client and upstream would do directly,
just proxied. This is the path your existing clients (an agent framework, a chat app with MCP
support) use without any changes beyond pointing them at Acropolis's URL instead of the upstream's.

**2026 client → 2025 upstream (the bridge):** this is the interesting case. Acropolis:

1. Maintains a cached `initialize` handshake with the upstream on the client's behalf — done
   once per upstream server, not once per stateless request, so a 2026 client's statelessness
   doesn't force a repeated handshake.
2. Translates the stateless request into the shape the 2025 upstream expects.
3. Consumes the upstream's `text/event-stream` response and extracts the single JSON-RPC
   result, returning it as a plain JSON body — a 2026 client never has to know the upstream
   replied with SSE at all.

Acropolis deliberately advertises no `sampling`, `elicitation`, or `roots` capability when it
establishes this handshake. Those are all "the server calls back into the client mid-request"
patterns, and a bridged 2026 client has no channel for Acropolis to relay that callback through
(see MRTR below) — so Acropolis tells 2025 upstreams up front not to attempt one.

**tools/list, filtered:** regardless of which generation asked, the tools a caller can
actually see reflect the server's current policy — a tool denied by policy simply isn't in the
list. This is true for both the per-server and aggregate endpoints.

**server/discover:** mandatory for 2026-generation servers, so Acropolis answers it for every
server it proxies — synthesized from whatever the upstream told it during the handshake
(protocol version, server info, capabilities), even for a 2025-generation upstream that's never
heard of this method.

## What's explicitly not supported yet

Two pieces of the 2026 spec are intentionally unimplemented, not silently broken:

**`subscriptions/listen`** (server-to-client push notifications over a long-lived stream) — a
2026 client that tries this gets a clean `-32601` (method not found), and Acropolis's
`server/discover` response never advertises the subscriptions capability, so a
spec-conforming client shouldn't attempt it in the first place.

**MRTR (Multi Round-Trip Requests)** — the mechanism a 2026-generation server would use to ask
its client a follow-up question mid-call. Since Acropolis tells every bridged 2025 upstream not to
attempt this (see above), it shouldn't come up in practice. If a 2025 upstream ever does try to
initiate a mid-call callback anyway, the bridge fails that specific call with a clear error
rather than silently hanging or dropping the callback.

Both of these are here because the entire real-world fleet of MCP servers today is
2025-generation with essentially zero use of notification traffic — implementing either would
be real engineering effort in service of a pattern nothing currently exercises. If you're
running a genuinely 2026-generation upstream server that needs either of these, that's the
signal this needs to be built — please open an issue rather than assuming it's coming
"eventually."

## What this means for you, practically

- You don't need to know or configure anything about protocol generations. Register your
  server's URL; Acropolis figures out how to talk to it.
- If you're building a 2026-generation client, point it at Acropolis the same way you'd point it
  at a native 2026 server — the stateless request shape, headers, and response format are the
  same either way.
- Policy (allow/deny/param rules/rate limits) applies identically regardless of which
  generation asked — the bridge sits below policy enforcement, not around it.
