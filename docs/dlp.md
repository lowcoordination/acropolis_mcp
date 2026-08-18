# DLP (data loss prevention) on tool arguments

Acropolis controls *which* tools an agent may call and *what shape* the arguments take
(allow/deny lists, param rules). Neither can express "this tool is fine, but don't let it
*carry* a credit card number." DLP fills that gap: it inspects the **values** inside a
`tools/call` request's arguments and, per-detector, lets the call through, redacts the matched
span, or blocks the call outright — before anything reaches the upstream.

This is opt-in, per-server, off-by-default. Configure it on the server detail page, under
**DLP (data loss prevention)**, next to the param-rule editor.

## Scope: arguments only, not responses — and why

**This feature scans tool call arguments. It does not scan tool call responses.** This is a
deliberate scope decision, not an oversight, made *before* any response-scanning code was
written — see the benchmark section below for the numbers that back it up.

Argument scanning touches a small JSON object that's already parsed for policy evaluation on
every `tools/call`. Response scanning is a different problem in kind:

- **Streaming.** Acropolis's passthrough path forwards upstream responses as a raw streamed
  body (`StreamingResponse` over `r.aiter_raw()` in `argus/pipeline.py`). Scanning a stream
  means either buffering it whole (defeats streaming, risks unbounded memory for a large
  response) or scanning incrementally across chunk boundaries — and a secret can straddle two
  chunks, which incremental scanning has to handle correctly or it's not actually safe.
- **Size.** A response body has no size cap today. Scanning needs one, and the behavior past
  that cap is a real, unresolved policy question: fail open (stop scanning, forward the rest
  unscanned — a leak) or fail closed (reject a response that's simply large and legitimate)?
  Neither answer is obviously right, and picking one without data would be a guess dressed up
  as a decision.
- **Bridged vs. passthrough.** The two forwarding paths in `argus/pipeline.py` handle response
  bodies differently already (the bridge parses and re-serializes JSON-RPC; passthrough streams
  raw bytes) — response scanning would need separate treatment and separate tests for each,
  roughly doubling the surface area of this feature.

The honest, measurement-backed call: land argument scanning, benchmark it, and use that
benchmark to decide whether response scanning is worth its cost — rather than build it
speculatively and find out later it doesn't fit the gateway's own latency budget.

## Detectors

Every detector inspects argument **values**, not just key names — the existing
`_SENSITIVE_ARG_KEY_RE`/`summarize_args()` in `argus/policy.py` (unchanged by this feature)
catches `{"api_key": "..."}` by looking at the key; it has always missed
`{"message": "my key is sk-live-abc123"}`, which is the realistic leak. DLP detectors look at
`"my key is sk-live-abc123"` itself.

| Detector | What it matches | False-positive mitigation |
|---|---|---|
| `credit_card` | 13–19 digit sequences, optionally grouped | **Luhn checksum** — a Luhn-invalid 16-digit number does not fire |
| `email` | `user@domain.tld` shape | — |
| `us_ssn` | `XXX-XX-XXXX` | Rejects SSA-reserved area (000/666/9xx), group (00), and serial (0000) values |
| `aws_access_key` | 20-char `AKIA…`/`ASIA…`/etc. | Prefix + length/charset format check (there is no public checksum algorithm for AWS key IDs — see `argus/dlp.py`'s comment on this) |
| `private_key_pem` | `-----BEGIN ... PRIVATE KEY-----` headers | — |
| `high_entropy_string` | 20–128 char token-alphabet runs | Shannon entropy ≥ 3.5 **and** ≥3 of 4 character classes present (lower/upper/digit/symbol) — a plain long English word does not fire; a mixed-case, digit-bearing token does |

Plus **operator-defined custom patterns** (`dlp_custom_patterns`): a name, a regex, and an
action, evaluated the same way as the built-ins.

## Actions: allow / redact / block

Each detector (built-in or custom) is independently set to one of three actions:

- **`allow`** — configured but inert. Exists so an operator can leave a detector "on the list"
  without it doing anything, e.g. while evaluating whether to enable it for real.
- **`redact`** — the matched span is replaced with a placeholder (`[REDACTED:<detector>]`) and
  the call proceeds with the rest of the argument intact. This is the feature's actual
  differentiator over a `block_patterns` param rule, which can only refuse a call outright.
- **`block`** — the call is refused (`403`, audited as `BLOCKED`) before it reaches the
  upstream.

When multiple detectors match the same request, `block` always wins over `redact` — a call
that's going to be refused doesn't get partially redacted first.

## Every detector defaults to OFF

`ServerPolicy.dlp_detectors` defaults to `{}` and `dlp_custom_patterns` defaults to `[]`. A
server with neither configured takes zero DLP-related code paths — `argus/policy.py`'s
`evaluate()` skips the scan entirely (`if policy.dlp_detectors or policy.dlp_custom_patterns:`)
and produces a `Decision` indistinguishable from pre-DLP Acropolis. This is enforced by a
regression test (`test_no_dlp_detectors_forwards_body_unmodified` in
`tests/integration/test_dlp_redaction.py`) that posts an argument containing a credit card
number, an email, and an AWS key to a server with no DLP config, and asserts the upstream
receives the exact original bytes.

This default is deliberate, not just cautious. A detector that's on and wrong is worse than a
detector that's off: false-positive redaction silently mangles a legitimate tool argument, and
the tool then fails somewhere downstream with no obvious connection back to "a DLP rule ate part
of my input." A clean block is loud and debuggable; a bad redaction is quiet and confusing.
Every detector shipping off by default, and every server needing an explicit opt-in per
detector, is the mitigation for that risk.

## Where this runs in the pipeline

Inside `argus/policy.py`'s `evaluate()`, **after** allow/deny mode and param-rule evaluation,
**before** the upstream forward:

1. Allowlist/denylist check
2. Param rules (`block_patterns`, `max_length`, etc.)
3. **DLP scan** (this feature)
4. Forward to upstream

A call that's going to be blocked by an earlier check never reaches the DLP scan — no point
paying for it. A `redact` decision mutates the arguments *before* `Pipeline._process` forwards
the request, by re-serializing the JSON-RPC envelope and substituting it via the `body_override`
seam already used by `AggregatePipeline` (de-namespacing tool names) and the in-UI tool tester —
this is the third consumer of that seam, not a new forwarding path.

The redacted body is what actually leaves the process. This is proven by an integration test
(`TestRedactActuallyMutatesForwardedBody` in `tests/integration/test_dlp_redaction.py`) using a
raw TCP socket listener standing in for the upstream — the assertion is against the literal
bytes read off the wire, not a mock's recorded call arguments.

## Audit safety: the matched value never appears in the audit log

A redaction (or block) audit row records **which detector fired and what action was taken** —
`dlp_detector`, `dlp_action`, `dlp_match_count` — and nothing else about the match. The matched
or redacted text itself never reaches `audit_events`. This required fixing a real gap found
during testing: `args_summary` (the existing audit-log field, unchanged in shape by this
feature) is built from the *original* arguments and only redacts by *key name*
(`_SENSITIVE_ARG_KEY_RE`) — an argument named `"message"` containing a credit card number would
sail into `args_summary` untouched even with the DLP detector correctly redacting the *forwarded*
body. `argus/policy.py`'s `evaluate()` now re-summarizes `args_summary` from the DLP-redacted
arguments whenever a detector fires (for both `redact` and `block`), so the audit-log path and
the wire path are consistent. This is covered by
`TestAuditRowNeverContainsMatchedValue`, which asserts on the fully serialized audit row text,
not just individual fields.

The same discipline applies to webhook payloads (`stoa/webhooks.py`): a `blocked` webhook event
carries `dlp_detector` (the name) but never the matched value, consistent with that feature's
existing exclusion of `args_summary` from every webhook payload.

## ReDoS safety on custom patterns

`dlp_custom_patterns` are operator-supplied regex — untrusted input, exactly the attack surface
the F2 security fix (`argus/policy.py`'s `_match_with_timeout`) was built for. Every custom
pattern match, including span recovery for `redact` (which needs match *positions*, not just a
yes/no), is bounded against catastrophic backtracking. Since the re2 fast path (issue #112),
patterns re2 accepts are matched inline in linear time — re2 cannot catastrophically
backtrack, so the whole scan (including every `finditer()` restart) runs directly on the event
loop in microseconds. Patterns re2 rejects (backreferences, lookarounds, ...) fall back to the
forkserver-isolated, wall-clock-bounded process F2 uses for `block_patterns`. A pathological
pattern on that fallback path — `^(a*)*\1$` (a backreference, hence re2-rejected) against a
crafted input, hangs Python's `re` engine for many seconds uninterrupted — times out and is
treated as **UNDETERMINED, which fails closed**: the entire argument value is treated as a
match (and blocked, or redacted to a single placeholder), never silently passed through.

One subtlety worth calling out explicitly: bounding only the *first* `search()` call is not
enough. `re.finditer()` restarts matching from each match's end position, and a pattern whose
first match resolves quickly is not guaranteed to resolve its second or third match equally
quickly — that's exactly the kind of position-dependent backtracking a ReDoS pattern exploits.
`argus/policy.py`'s `_finditer_spans_with_timeout` bounds the **entire** finditer call (all
positions, all matches) inside one timeout-guarded subprocess, not just a single confirmatory
search followed by an unguarded finditer. See `test_finditer_spans_with_timeout_fails_closed_on_pathological_pattern`
in `tests/unit/test_policy.py`.

Built-in detector patterns are curated and fixed at deploy time (not editable through the web
UI), so the *pattern text* is not operator-supplied the way `dlp_custom_patterns` is — they're
matched directly, without the forkserver overhead, which is why the benchmark below shows
built-in-only scanning costs sub-millisecond while a single custom pattern costs ~150ms
(dominated by the forkserver's fixed process-spawn cost, not by the pattern or argument content
— see F2's own documentation in `argus/policy.py` for why that overhead is an accepted trade for
correctness on a security-critical path).

**"Curated" is not automatically "safe," and this was found the hard way during this PR's own
self-review, not caught in initial design.** The original `email` detector pattern —
`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`, a hand-written pattern with no operator
input involved — was itself vulnerable to catastrophic backtracking: confirmed at ~15 seconds
against `"a."*20000 + "@" + "b."*20000`, because `.` appeared both inside a repeated character
class and as the literal separator immediately after it, an ambiguous-overlap shape in the same
family as the textbook `(a+)+` ReDoS example, just far less obvious to spot by inspection. The
value being scanned (the tool call argument) is *always* untrusted regardless of where the
pattern came from — a curated pattern narrows the attack surface to "did the author get the
regex right," it does not eliminate it.

Routing every built-in match through the forkserver was considered as the general fix and
rejected: benchmarked at ~150ms of overhead *per detector per argument* (see below), enabling
all 6 built-ins would add roughly 900ms to every scanned call, which would violate this
feature's own "DLP scanning must stay fast" premise to guard against a bug class whose real fix
is pattern-level, not infrastructure-level. The fix actually applied: rewrite the specific
vulnerable pattern to a structurally non-ambiguous form (verified against both the specific
adversarial input and a 15-iteration randomized fuzz sweep, worst case <2ms), and add a
permanent regression test (`test_all_builtin_detector_patterns_resist_randomized_fuzz` in
`tests/unit/test_dlp.py`) fuzzing every current built-in pattern — the bar any future addition
to `BUILTIN_DETECTORS` must also clear before shipping.

## Performance

DLP scanning inherits the existing `max_body_bytes` guard (default 1MB, enforced in
`Pipeline._read_body_guarded` before the request body is even parsed) — an argument-scan cost
that scales with argument size is therefore bounded by the same cap that already protects every
other part of request handling, not a new unbounded surface this feature introduces.

Measured with `tests/bench/bench_dlp.py` (`python -m tests.bench.bench_dlp`), 300 iterations per
cell, on representative argument sizes (small: ~36 bytes, medium: ~1KB, large: ~20KB):

**Built-in detectors only (6 detectors, no custom patterns):**

| Argument size | Added p50 | Added p99 |
|---|---|---|
| Small (~36B) | 0.007ms | 0.009ms |
| Medium (~1KB) | 0.057ms | 0.069ms |
| Large (~20KB) | 1.062ms | 1.102ms |

**With one operator-supplied custom pattern added (forkserver-routed):**

| Argument size | Added p50 | Added p99 |
|---|---|---|
| Small (~36B) | ~148ms | ~175ms |
| Medium (~1KB) | ~147ms | ~172ms |
| Large (~20KB) | ~148ms | ~193ms |

Two takeaways:

1. **Built-in-only scanning is cheap and scales sub-linearly with argument size** — the added
   cost at 20KB (~1.1ms p99) is nowhere near enough to be user-visible on a gateway request.
2. **Every custom pattern adds a roughly fixed ~150-190ms**, dominated by the forkserver
   process-spawn cost documented in `argus/policy.py` (measured there at ~22ms per spawn; this
   feature's overhead is higher because span recovery may involve a second internal pass inside
   the same guarded subprocess). This cost is *per custom pattern configured on the server*, not
   per byte scanned — an operator adding several custom patterns should expect the cost to scale
   with pattern count, not argument size. This is the real, load-bearing reason custom patterns
   are a deliberate, visible opt-in rather than bundled into the default detector set.

**The response-scanning deferral, quantified:** extrapolating the built-in-only scanning rate
(~0.055ms added p99 per KB) to response-sized payloads projects to ~0.55ms at 10KB, ~5.5ms at
100KB, and ~55ms at 1MB — response bodies routinely exceed all of these sizes, and that number
doesn't even account for the streaming-chunk-boundary and size-cap problems described above,
which argument scanning never has to solve. This is a **projection from argument-scanning
measurements**, explicitly not a benchmark of a real response-scanning implementation (none
exists) — but it's specific enough to make the "measure before building" call defensible rather
than a hand-wave. If response scanning is built in a future PR, this projection is the number to
beat, and to re-derive from a real implementation before shipping it.

## Explicitly out of scope: encoding evasion

**This feature does not defeat, and does not attempt to defeat, base64 encoding, URL-encoding,
or unicode homoglyph substitution.** A credit card number encoded as base64
(`NDExMTExMTExMTExMTExMQ==`) or with digits replaced by visually similar unicode characters will
not be caught by any detector here — the regexes match literal, plaintext patterns.

This is a real gap, named explicitly rather than implied away: **overclaiming DLP completeness
is worse than a narrow, honest scope.** A detector that silently misses encoded secrets while a
security team believes "DLP is on" for a server is a worse outcome than no DLP at all, because it
creates false confidence. Defeating encoding evasion is a materially different feature — it needs
decode-then-scan heuristics (with their own false-positive and performance costs: is
`aGVsbG8=` worth base64-decoding on every scan?) — and is not attempted here.

If this matters for your threat model: treat this feature as raising the floor against
*accidental* leaks (an agent pastes a real secret into a tool argument in plaintext, which is
the overwhelmingly common real-world case this exists for) — not as a defense against a
sophisticated actor deliberately trying to exfiltrate data past it.

## Config: `ServerPolicy` fields

```python
dlp_detectors: dict[str, str]         # detector name -> "allow" | "redact" | "block"
dlp_custom_patterns: list[DlpCustomPattern]  # {name, pattern, action}
```

Stored on `server_policies.dlp_config` as a single JSON column (migration
`0008_gateway_dlp_config.sql`). **Correction to the original plan doc**, documented here because
it changes what shipped: the plan assumed `ServerPolicy` was already stored as JSON and this
would "ride the existing column, no migration needed." That premise doesn't hold for this
codebase — `server_policies`/`tool_policies`/`param_rules` are normalized SQL tables (see
`ServerRepo.set_policy`/`get_policy` in `db/repo.py`), not a JSON blob, so there was no existing
column to ride. A real migration was required; see that migration file's comment for the full
reasoning on why a single JSON column (rather than further normalized per-detector rows) was the
right shape for this specific piece of config.

What *does* hold from the plan without correction: **config export/import carries DLP config for
free**, because `export_config`/`plan_import` in `archon/config_io.py` already serialize/parse
the whole `ServerPolicy` object generically via `model_dump()`/`ServerPolicy(**dict)` rather than
enumerating fields — adding `dlp_detectors`/`dlp_custom_patterns` to the model was sufficient,
with zero changes needed in `config_io.py` itself. Verified with a round-trip test
(`test_export_round_trips_dlp_config_faithfully` / `test_import_of_exported_dlp_config_reports_unchanged`
in `tests/integration/test_config_io.py`) rather than assumed.

## Admin audit trail

Changing a server's DLP config is a security-lowering/relevant action and is recorded in the
control-plane audit log (`admin_events`, enterprise #4's infrastructure) the same way any other
policy change is — `archon/admin_audit.py`'s `record_policy_change` diffs `dlp_detectors` and
`dlp_custom_patterns` alongside `mode`, `allowed`, `denied`, and `param_rules`. The recorded
before/after state includes detector names, actions, and custom pattern names/regex text (all
operator-authored *configuration*, safe to record) — never a matched runtime *value* (which
never reaches this or any other audit surface, see above).

## Tool tester parity

The in-UI "Try it" tool tester (`POST /api/v1/servers/{slug}/test-call`) dispatches through the
exact same `Pipeline.handle()` → `evaluate()` path a real client's `tools/call` does, so it shows
the identical DLP decision — same detector, same action, same redacted response — that a raw
`curl` call against the same server would get. This is the same tester/curl parity guarantee the
tool tester feature originally established for allow/deny/param-rule decisions; DLP does not
introduce a second evaluation path that could drift from it.
