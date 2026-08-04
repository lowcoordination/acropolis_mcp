# Policy cookbook

Every server registered in Acropolis has a policy: a mode, an allow/deny list, optional
per-parameter rules, and an optional rate limit. This page is worked examples for common
situations — everything here can be set through the **server detail page** in the UI, or via
`PUT /api/v1/servers/{slug}/policy` directly if you'd rather script it.

## The three modes

| Mode | Behavior |
|---|---|
| `passthrough` | Every tool call is allowed. Still logged. This is the default for a newly-added server. |
| `allowlist` | Only tools in `allowed` may be called. Everything else is blocked. |
| `denylist` | Every tool may be called *except* those in `denied`. |

Pick allowlist when you know exactly what a client needs and want everything else closed by
default (safer, more maintenance when the upstream adds tools). Pick denylist when a server
has one or two genuinely dangerous tools and everything else is fine (less maintenance, but a
new dangerous tool added upstream is allowed by default until you notice and deny it).

Parameter rules apply **regardless of mode** — even in `passthrough`, a param rule you've set
still blocks a matching call. Mode controls whether the *tool* is reachable at all; param
rules constrain *how* an allowed tool is called.

## Recipe: read-only filesystem access

A filesystem MCP server usually exposes both read and write tools. If a client only needs to
read:

```json
{
  "mode": "allowlist",
  "allowed": ["read_file", "read_multiple_files", "list_directory", "directory_tree", "search_files", "get_file_info"],
  "denied": [],
  "param_rules": {}
}
```

`write_file`, `create_directory`, `move_file`, and `edit_file` (or whatever your server calls
them) simply aren't in the list — any call to them is blocked before it reaches the upstream.

## Recipe: shell access with a real safety net

If you have a server that runs shell commands, allowlist the specific tool and add a param
rule on the command argument itself — a length cap plus a blocklist of patterns that should
never appear:

```json
{
  "mode": "allowlist",
  "allowed": ["shell_run"],
  "denied": [],
  "rate_limit": "5/minute",
  "param_rules": {
    "shell_run": {
      "command": {
        "max_length": 200,
        "block_patterns": [
          "rm\\s+-rf",
          "sudo",
          "curl.+\\|.+sh",
          "wget.+\\|.+sh"
        ]
      }
    }
  }
}
```

`block_patterns` are regular expressions, matched case-insensitively against the argument's
string value. A pattern that matches blocks the call with a clear reason in the audit log
(`rule: block_pattern`, `matched: <the pattern>`). The `rate_limit` here also caps this
specific server to 5 calls per minute regardless of which tool is called — useful as a second
line of defense against a client stuck in a retry loop.

Treat a blocklist like this as a speed bump, not a sandbox — regex matching on a command
string can't catch every way to express the same intent. If a tool is dangerous enough that
you don't trust a blocklist, deny it outright instead.

### What happens if a pattern is slow

Every `block_patterns` match runs with a hard 0.5s timeout in an isolated process, so a
pathological regex (accidentally vulnerable to catastrophic backtracking, or just slow against
unusually long input) can never hang a request or stall the event loop. If a match can't
complete in time — whether because the pattern is genuinely slow or the gateway is under heavy
concurrent load — **the call is blocked**, the same as an actual match. The audit log records
this as `rule: block_pattern_undetermined` rather than `block_pattern`, so you can tell the two
apart.

This is a deliberate fail-*closed* choice: a rule you explicitly wrote should never silently
stop enforcing just because the gateway is busy. If you see `block_pattern_undetermined`
appearing regularly in the audit log, it usually means the pattern itself needs simplifying
(anchor it more tightly, avoid nested quantifiers like `(a+)+`) rather than the gateway being
overloaded — a well-formed pattern against realistic input completes in well under a
millisecond.

## Recipe: deny a parameter outright (the SSRF case)

Some tools take a parameter that's fine most of the time but dangerous in a specific shape —
classically, a `proxies` or `url` argument that could be pointed at an internal service
(server-side request forgery). Rather than trying to blocklist every bad value, deny the
parameter entirely:

```json
{
  "mode": "allowlist",
  "allowed": ["search_jobs"],
  "denied": [],
  "param_rules": {
    "search_jobs": {
      "proxies": { "denied": true }
    }
  }
}
```

Any call that includes a `proxies` argument at all is blocked, regardless of its value. The
tool still works fine for callers who don't pass that argument.

## Recipe: block path traversal on a file-reading tool

```json
{
  "mode": "allowlist",
  "allowed": ["read_file", "list_directory"],
  "denied": [],
  "param_rules": {
    "read_file": {
      "path": {
        "block_patterns": ["\\.\\./", "^/etc/"]
      }
    }
  }
}
```

This blocks `../`-style traversal attempts and direct reads from `/etc/`, while leaving
ordinary paths untouched.

## Recipe: numeric bounds

`max_value` and `min_value` work on any parameter that can be coerced to a number — useful for
capping something like a "how many results" argument that could otherwise be used to pull an
unreasonable amount of data in one call:

```json
{
  "mode": "passthrough",
  "param_rules": {
    "search_jobs": {
      "results_wanted": { "max_value": 50 }
    }
  }
}
```

A non-numeric value for a parameter with `max_value`/`min_value` set is left alone (the rule
simply can't apply to it) — this is for capping a number, not for type-checking.

## A note on the aggregate endpoint

Everything above is per-server. If you also use the aggregate `/mcp` endpoint (tools from
every `in_aggregate` server merged into one connection, namespaced `<slug>__<tool>`), the same
per-server policy still applies — a tool blocked on its own server is blocked the same way
through the aggregate, and blocked tools don't appear in the aggregate's `tools/list` either.
There's no separate policy to maintain for the aggregate view.
