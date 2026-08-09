# Pluggable secret backends

Acropolis stores one live third-party credential: `upstream_auth_header` on a registered
server — the `Authorization` header value injected on outbound requests to that server's
upstream. Before this feature it was always a plaintext string in `gateway.db`. Now
`servers.upstream_auth_header` can hold either a **literal** (unchanged, today's behaviour) or a
**reference** — a `vault://...` or `enc:v1:...` string resolved to its plaintext at call time by
a pluggable `SecretProvider`.

## The three tiers

Select with the `ACROPOLIS_SECRET_PROVIDER` env var (`local` | `encrypted` | `openbao`; default
`local`). This is a process-level setting, not something changed per-request or per-server — every
server on one Acropolis instance resolves through the same provider.

### `local` — plaintext (default)

Pass-through. A literal typed into the server form is stored and read back exactly as-is — this
is **byte-identical to pre-feature behaviour**, and it's the regression guard for this entire
item: the full pre-existing test suite passes unchanged with `local` selected, because `local`
selected *is* the pre-feature code path.

Use this if you're not ready to run an external key or a Vault/OpenBao instance. It's what every
existing Acropolis install already runs, unchanged.

### `encrypted` — AES-256-GCM envelope encryption

A literal typed into the server form is encrypted at write time and stored as
`enc:v1:<base64(nonce || ciphertext || tag)>`. Resolved back to plaintext at call time using a
32-byte data key from:

1. `ACROPOLIS_SECRET_KEY` — the key itself, as 64 hex characters or standard base64.
2. `ACROPOLIS_SECRET_KEY_FILE` — a path to a file containing the same.

One of these is required when `encrypted` is selected; there is no default key. Generate one with:

```bash
openssl rand -hex 32
```

The `v1` version prefix means the ciphertext format can change later (a different AEAD, a
different KDF, a wrapped-DEK/KMS scheme) without breaking data already encrypted under `v1` — a
future provider version dispatches on the prefix and can still decrypt old data.

> [!WARNING] Threat model — read this before trusting this tier for anything
>
> **This defends backup and snapshot leakage**: a stolen `gateway.db` file, a leaked
> `sqlite3 .backup` copy (see [backup-and-upgrades.md](backup-and-upgrades.md)), a volume
> snapshot that ends up somewhere it shouldn't. Without the key — which is never itself stored in
> the database — the ciphertext in `upstream_auth_header` is useless.
>
> **This does NOT defend a live host compromise.** If an attacker has code execution on the
> running Acropolis process, or read access to wherever `ACROPOLIS_SECRET_KEY` /
> `ACROPOLIS_SECRET_KEY_FILE` is configured (an env var, a mounted file, a compose/k8s secret),
> they can decrypt everything the application can decrypt — the same way the application itself
> does on every call. That is not a bug to fix later; it's what "the app needs the plaintext to
> authenticate outbound calls" necessarily means for any software running as one process.
>
> **A key file sitting in the same volume as `gateway.db` provides zero real protection.** It
> defeats the entire point of this tier: an attacker (or a backup) that gets the database gets
> the key sitting right next to it. Put the key somewhere the database backup doesn't reach — a
> separate secret store, a different volume, an env var injected only into the running
> container/pod and never persisted to disk alongside the data directory.
>
> Overclaiming what `encrypted` buys you is worse than not building it. State the boundary
> plainly: this is AES-GCM-with-an-external-key, defending the realistic homelab threat of a
> leaked backup — not a substitute for host security.

### `openbao` — a generic HashiCorp Vault KV v2 client

Despite the name (kept for consistency with this codebase's existing terminology), this is a
**generic Vault KV v2 HTTP API client** — it works identically against real HashiCorp Vault,
OpenBao, or any other server implementing the same wire protocol
(`GET/POST/DELETE /v1/<mount>/data/<path>`, `X-Vault-Token` header auth). Nothing in the client
assumes a specific deployment, mount layout, or network location beyond what you configure.

Reference format: `vault://<mount>/<path>#<key>` — e.g. `vault://secret/acropolis/github#token`
reads the `token` field of the secret at `secret/data/acropolis/github` (KV v2 nests the actual
data under `data` server-side; the client handles that automatically — the reference itself uses
the same path shape `vault kv get` does, not the raw HTTP path).

Configuration (env vars, all under `ACROPOLIS_`):

| Var | Required | Purpose |
|---|---|---|
| `VAULT_ADDR` | yes | Base URL, e.g. `https://vault.example.internal:8200` |
| `VAULT_TOKEN` | one of these two | Static token auth |
| `VAULT_ROLE_ID` + `VAULT_SECRET_ID` | | AppRole auth (nice-to-have; logs in once, caches the resulting token for its lease) |
| `VAULT_TTL_SECONDS` | no (default 60) | Resolved-value cache TTL — see below |

**Writing secrets into Vault is a manual, out-of-band step.** Acropolis does not write a literal
you type into the server form into Vault on your behalf — there's no way to infer what
mount/path/key you'd want it filed under. Write it yourself:

```bash
vault kv put secret/acropolis/github token="ghp_..."
# or: bao kv put secret/acropolis/github token="ghp_..."
```

then paste `vault://secret/acropolis/github#token` into the server's credential field.

## Resolution timing: call time, not startup

Every tier resolves `upstream_auth_header` **at the moment a call needs it** — the proxied
forward, the health probe, and `tools/list` — never at server-registration time or at process
startup. `openbao` additionally caches a resolved value for a short TTL (`VAULT_TTL_SECONDS`,
default 60s).

This is a deliberate behavioural requirement, not just a performance nicety:

- **Startup resolution would mean a Vault outage at boot permanently breaks every server** until
  the process restarts — an unrelated dependency's blip taking down every proxied call for
  however long the process happens to stay up.
- **A short TTL cache means credential rotation in Vault propagates within the TTL window**,
  without restarting Acropolis. Rotate the secret in Vault; the next resolution past the TTL
  picks up the new value.
- **A Vault blip degrades gracefully**: a cached value keeps working until it expires; only a
  resolution attempted *after* the cache has expired, against a still-unreachable Vault, fails —
  and it fails loudly (see below), not silently.

## Failure is always explicit, never silent

If resolving `upstream_auth_header` fails — a malformed reference, a wrong encryption key, Vault
unreachable, a 403 from Vault, a missing key in the secret — the call is answered with a clear
JSON-RPC error (HTTP 502) and an `ERROR` audit row. **The call is never forwarded to the upstream
without the credential.** Forwarding unauthenticated on a resolution failure would turn a secrets
outage into a confusing upstream-401 storm, and could plausibly leak a request to an upstream that
expected auth on a code path that assumed it always had one.

The health poller applies the same rule: a server whose secret won't resolve reads `unhealthy`
with a **distinguishable** reason (`health_reason` on the server, prefixed `secret resolution
failed: ...`) rather than a generic probe failure — you can tell "this server's Vault reference
broke" apart from "this server's process is down" at a glance, in the UI and via the API.

## References are not secrets

A `vault://...` or `enc:v1:...` reference is *meaningless* without separate access to the Vault
instance it points at, or the encryption key it was made with — so it is not treated as a secret
by the rest of the product:

- **Config export**: a reference is always included, with no `PLAINTEXT` warning. A literal is
  still omitted by default and triggers the existing warning exactly as before — see
  [backup-and-upgrades.md](backup-and-upgrades.md#exporting-and-importing-configuration).
  This is what makes committed, reviewable configuration (and policy-as-code) practical with real
  credentials: point two Acropolis instances at the same Vault, and the *same* exported file with
  the *same* `vault://` reference works on both, without ever putting the credential in the file.
- **`has_upstream_auth_header`**: stays `true` for a reference exactly as it does for a literal —
  a reference means "a credential is configured," same as today.
- **The UI**: the server list and detail pages show whether a credential is configured and, if
  so, whether it's externalized (a reference) or a literal — never the value itself, on any tier.

## What's never logged or audited, on any tier

- The resolved plaintext credential.
- The `encrypted` tier's data key.
- The `encrypted` tier's ciphertext, logged gratuitously (there's no operational reason to; it's
  not itself sensitive, but logging secret-adjacent material for no reason is still worth not
  doing).

A change to `upstream_auth_header` **is** a control-plane audit event
(`server.secret_reference_change` — see [audit-and-compliance.md](audit-and-compliance.md)): it
records the server slug and a shape classification (was/is something configured, was/is it a
reference vs. a literal) so an operator reviewing the audit trail can see *that* a credential
changed and *what kind* of change it was — never the value, before or after, on either side of
the change.

## No migration required

`upstream_auth_header` was already a plain `TEXT` column (added in migration `0003`, F23). This
feature adds no migration for it — a literal already in the database is read as a literal by
`local` (the default), byte-identical to before. Switching to `encrypted` or `openbao` does not
retroactively transform existing literals; only a value written or edited *after* switching tiers
goes through the new tier's write path. If you want to migrate existing literals to a new tier,
re-save each server's credential through the UI/API after switching — the write path will do the
right thing for whichever tier is now active.
