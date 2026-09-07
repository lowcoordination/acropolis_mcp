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

### Allow patterns: blast-radius limits

`block_patterns` can only say "never match this." Some constraints go the other way: an agent
should be able to write files, but only *inside a project directory*. Inverting that into a
blocklist means enumerating everything it must not write to — unbounded, and wrong. For that,
a param rule accepts `allow_patterns`: a list of regular expressions the value must match
**at least one** of, or the call is blocked:

```json
{
  "param_rules": {
    "write": {
      "path": {
        "allow_patterns": ["^/home/lowcoordination/k3s/manifests/"]
      }
    }
  }
}
```

Five properties, all deliberate — don't infer the unstated inverse of any of them:

- **Empty `allow_patterns` means no allow constraint.** An empty list behaves exactly like a
  policy without the field at all — it is not an "allow nothing" rule.
- **Deny wins.** A value matching both an `allow_patterns` entry and a `block_patterns`
  entry is **blocked**. Block checks run first, and the blocklist is the stronger
  expression of intent. The opposite precedence (an allow match carving an exception out of
  the blocklist) is defensible for some setups — if you want that, it must be a deliberate
  request, not a silent default.
- **Undecidable is not permitted.** If an allow-pattern match can't be decided (timeout,
  worker failure — same machinery as above), it counts as *not matched*, and if no pattern
  matched determinately the call is **blocked**, recorded as
  `rule: allow_pattern_undetermined`. "I could not verify this is permitted" never means
  permit. One caveat: if any pattern in the list matches determinately, the call passes even
  if a different pattern in the same list was undetermined — a verified match satisfies
  "at least one" outright.
- **An omitted parameter is not constrained.** A param rule only runs when the parameter is
  actually present in the call. If the caller omits `path` entirely, the rule above does not
  fire and the call proceeds — an allow-list constrains *the value that was sent*, it does not
  make the parameter mandatory. This matters more for `allow_patterns` than for
  `block_patterns`: with a blocklist an absent value is genuinely harmless, but a blast-radius
  limit can be sidestepped by a caller that simply omits the parameter and lets the tool apply
  its own server-side default. If a tool behaves that way, an `allow_patterns` rule on that
  parameter is not sufficient on its own — deny the tool, or constrain it upstream.
  (Making a parameter mandatory is tracked separately as `ParamRule.required`, issue #131.)
- **Patterns match case-insensitively.** Every operator pattern compiles case-insensitive (the
  same for `block_patterns`). For a blocklist that is the conservative direction — it catches
  more. For an allow-list it is the *permissive* direction: `^/home/lowcoordination/k3s/` also
  admits `/HOME/LOWCOORDINATION/K3S/`, which on a case-sensitive filesystem is a different
  path entirely. Write allow patterns knowing they are looser than they look.

`allow_patterns` use the same engine dispatch as `block_patterns` (re2 fast path, forkserver
fallback with the same hard timeout), and a block for missing the allow-list is recorded as
`rule: allow_pattern`.

### What happens if a pattern is slow

Every `block_patterns` match runs with a hard 0.5s timeout (`ACROPOLIS_REGEX_MATCH_TIMEOUT_
SECONDS`) in an isolated process, so a pathological regex (accidentally vulnerable to
catastrophic backtracking, or just slow against unusually long input) can never hang a request
or stall the event loop. If a match can't complete in time, **the call is blocked**, the same
as an actual match. The audit log records this as `rule: block_pattern_undetermined` rather
than `block_pattern`, so you can tell the two apart.

This is a deliberate fail-*closed* choice: a rule you explicitly wrote should never silently
stop enforcing just because the gateway is busy or a worker couldn't start.

**Most patterns never touch the process path at all.** Since the re2 fast path (issue #112),
any pattern re2 accepts is matched inline on the event loop in microseconds — re2 is linear
time by construction, so there is nothing to time out. Only patterns re2 rejects
(backreferences, lookarounds, ...) fall back to the timeout-guarded worker process described
below, and the fail-closed `block_pattern_undetermined` outcome applies to those. "The match
itself was slow" below is therefore about the fallback path; a pattern on the re2 path cannot
be slow against any input.

Starting a match involves forking an isolated worker process first, then running the pattern in
it — two different things can make that time out, and the gateway logs them differently because
the fix for each is different:

- **The match itself was slow** (logged as *"exceeded Ns — this pattern is likely vulnerable to
  catastrophic backtracking"*): the worker started fine, but `pattern.search()` didn't finish in
  time. This usually does mean the pattern needs simplifying — anchor it more tightly, avoid
  nested quantifiers like `(a+)+`. A well-formed pattern against realistic input completes in
  well under a millisecond once the worker is running.
- **The worker never started in time** (logged as *"worker did not become ready"*): the pattern
  was never the bottleneck — this host (or its forkserver) couldn't fork and bootstrap a worker
  process fast enough, most often right after a restart (the forkserver helper itself hasn't
  been spawned yet) or under heavy concurrent load. Rewriting the pattern will not help. If you
  see this regularly, consider raising `ACROPOLIS_WORKER_READY_TIMEOUT_SECONDS` (default 5s) or
  investigating host performance — the gateway logs a boot-time warning if a warm match already
  eats a large share of the match budget on your hardware, which is a good early signal that
  this budget is running tight before it starts causing spurious blocks.

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

## Evaluating a call without making it

`POST /api/v1/policy/evaluate` answers "would this be blocked?" against a server's policy and
returns the decision. Nothing is forwarded upstream; no `tools/call` is made.

It exists for callers that are not MCP clients — chiefly a local agent guard that intercepts a
proposed `bash`/`write`/`edit` before it runs, and needs the same policy and the same audit
trail as the gateway's HTTP traffic.

```
POST /api/v1/policy/evaluate
Authorization: Bearer acropolis_...

{ "server": "prod-shell", "tool_name": "bash",
  "arguments": {"command": "fsck -y /dev/sda1"} }

200 { "blocked": true,
      "reason": "param 'command' failed rule 'block_pattern': fsck -y",
      "rule": "block_pattern", "matched": "fsck -y" }
```

The response carries exactly four fields. `matched` is the **operator's pattern**, never the
caller's argument text — see [DLP](dlp.md)'s audit-safety invariant.

**Authentication is an API key, not a session** — this is the one route under `/api/v1` that
works that way, and `auth_mode: open` does not apply to it. See
[Authentication](authentication.md#the-evaluation-endpoint-is-api-key-authenticated).

### Callers must fail closed

**Any response that is not `200` with a well-formed body must be treated as `blocked: true`.**
That includes `401`, `403`, `404`, `413`, `422`, `429`, every `5xx`, a timeout, a connection
refusal, and an unparseable body. Only an explicit `200 {"blocked": false}` permits the call.

This is not defensive style, it is the whole security property. A guard that treats an
unreachable gateway as permission has no value: the cheapest way to defeat it is to make the
gateway unreachable.

Set an explicit client-side timeout — a few seconds is ample, since the gateway's own
`block_pattern` match budget bounds the server side (see [What happens if a pattern is
slow](#what-happens-if-a-pattern-is-slow)) — and treat its expiry as a block.

This is a deliberate availability trade, and worth being explicit with your users about:
**gateway down means the agent cannot run local commands.** That is the intended behaviour. If
that trade is wrong for your deployment, the answer is to make the gateway highly available, not
to fail open.

`429` deserves a specific note because a busy guard will actually hit it: a rate-limit or quota
refusal is still a block, not a retryable "unknown". A caller may back off and retry rather than
failing the user's action outright, but it must not proceed in the meantime.

### It consumes the same budgets as real traffic

An evaluation runs the same regex engine as a real `tools/call` — including the forkserver
subprocess for patterns re2 rejects — so it is metered identically:

- It draws on the **same** `srv:{slug}` rate-limit bucket as data-plane calls, so a caller
  cannot double an effective budget by alternating surfaces. See [Rate limiting](rate-limiting.md).
- It counts against the API key's quota. A guard that evaluates and then executes spends **two**
  quota units per executed call. See [Quotas](quotas.md).

Every evaluation writes an audit row with `endpoint="policy-evaluate"` and an `origin` of
`local:<key-name>` — plus `/<harness>@<host>` when the caller sends the optional `harness` and
`host` fields, which is how a fleet answers "which machine, which agent". Those rows are kept out
of `/stats` so they never inflate traffic counters, and `?origin_class=local` filters to them.
See [Audit and compliance](audit-and-compliance.md#the-origin-scheme).

> **Known gap (#125):** `summarize_args` redacts argument values by **key name**. A secret
> passed as `{"password": "..."}` is redacted in the audit row; a secret sitting inline in a
> command string — `--from-literal=password=hunter2` — is truncated but **not** redacted. This
> applies equally to a real `tools/call` with the same argument; the evaluation endpoint does not
> add exposure, but a local guard sends command strings on every call, so it meets the gap more
> often. The response body is unaffected either way.

## A note on the aggregate endpoint

Everything above is per-server. If you also use the aggregate `/mcp` endpoint (tools from
every `in_aggregate` server merged into one connection, namespaced `<slug>__<tool>`), the same
per-server policy still applies — a tool blocked on its own server is blocked the same way
through the aggregate, and blocked tools don't appear in the aggregate's `tools/list` either.
There's no separate policy to maintain for the aggregate view.
