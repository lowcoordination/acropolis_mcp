# Webhook alerts

Acropolis's audit trail is pull-based: you find out a tool was blocked by opening the Audit
page. Webhook alerts push a notification instead, for the two events an operator actually wants
to hear about without watching a dashboard:

- **A tool call is blocked.**
- **A server transitions healthy → unhealthy** (the edge only — not every poll while a server
  stays down).

Configure it under **Settings → Alerts**, or via `PUT /api/v1/settings`
(`webhook_url`, `webhook_enabled`, `webhook_events`).

## This is an SSRF-sensitive feature — read this before enabling it

A gateway that POSTs to an operator-supplied URL is, by construction, a thing that can be
pointed at internal infrastructure. The mitigations below aren't optional hardening; they're
why this feature is safe to ship at all.

- **`https://` only**, and the target must resolve to a public address. Loopback, link-local
  (including the cloud metadata endpoint, `169.254.169.254`), RFC1918 private ranges, other
  reserved ranges, and multicast are all rejected **by default** — deliberately stricter than
  the upstream-server URL validator, which allows private-LAN addresses because registering a
  private MCP server is this product's normal use case. A webhook target is different: it's a
  thing the gateway posts to unattended, forever, on a much weaker signal of operator intent.
  Check `webhook_allow_private` in the settings API (or the checkbox in the UI) if you're
  genuinely posting to a LAN collector.
- **Redirects are never followed.** A URL that resolves to a public address at save time could
  redirect to `169.254.169.254` at send time — pre-flight validation alone can't catch that.
- **A short, fixed timeout** (5s), independent of the tool-call timeout — a slow or hung
  receiver never adds latency to a real request. Delivery is fire-and-forget on a background
  task.
- **Debounce and a hard cap.** Repeated blocks against the same server+rule within 60s collapse
  into one notification carrying a count, rather than one webhook per request. A misconfigured
  policy that blocks everything is capped at 20 deliveries/hour; once tripped, the next window
  (or shutdown) sends exactly one "N alerts suppressed" notice — silence and "nothing happened"
  must never look the same on the receiving end.

What pre-flight validation does **not** cover: DNS rebinding, where a hostname legitimately
resolves to a public address when you save the URL but to a private one when the webhook
actually fires. The redirect protection above closes the more common exploit shape of this
class of bug; a fully rebinding-proof design would need to pin and reuse the resolved IP across
validation and every future send, which this feature does not currently do.

## Payload and verification

```json
{
  "event": "blocked",
  "ts": "2026-08-06T00:00:00+00:00",
  "server_slug": "shell",
  "tool": "read_file",
  "rule": "block_pattern",
  "matched": "^/etc/",
  "reason": "denied by policy",
  "count": 1
}
```

`event` is one of `blocked`, `unhealthy`, `suppressed`, or `test` (from the "Send test webhook"
button). `count` is 1 for a single event, or the number of debounce-collapsed repeats /
suppressed alerts for `blocked` and `suppressed` respectively.

Tool **arguments are never included** — `args_summary` stays internal to the audit log. This is
data leaving the gateway to a third-party endpoint, and argument values may contain anything a
caller passed to a tool.

A per-instance secret is generated the first time you set a webhook URL (never shown again, same
show-once posture as an API key). Every delivery carries:

```
X-Acropolis-Signature: sha256=<hmac-sha256 of the exact request body, hex-encoded>
```

Verify it by recomputing the HMAC over the raw bytes you received, using the secret, and
comparing in constant time. There's no other way to fetch the secret after the fact — if you
lose it, save a new webhook URL to generate a fresh one.

## Testing your receiver

Use **Settings → Alerts → Send test webhook** (or `POST /api/v1/webhooks/test`) — it sends an
`event: "test"` payload immediately, bypassing debounce and the cap, and reports the outcome
(status code or connection error) right in the UI. A webhook you can't verify is a webhook you
don't trust; don't rely on waiting for a real block to confirm delivery works.
