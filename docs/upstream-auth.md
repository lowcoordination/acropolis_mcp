# Upstream authentication (Acropolis → fleet)

Acropolis mints short-lived, audience-bound JWTs and injects them on the hop to every registered
MCP server. The servers verify them with the shared `mcp-authn` Go middleware. This is distinct
from the client→Acropolis auth in [authentication.md](authentication.md): clients still use API
keys, and the fleet token proves only one bit — *this request came from Acropolis recently*.

## Why

Without it, every Acropolis security property (policy, DLP, rate limits, quotas, audit) is
voluntary: anything that can reach a server's URL bypasses the gateway. The token layer plus a
NetworkPolicy lockdown (k3s#81) make Acropolis the only path.

## The three credential modes

`servers.credential_mode`:

| Mode | Behaviour |
|---|---|
| `none` | No credential (the default). |
| `static` | Use `upstream_auth_header` (literal or secret reference) — the pre-#134 behaviour. |
| `token` | Mint an audience-bound JWT; ignore `upstream_auth_header`. |

> **Note:** `none` and `static` are currently behaviourally identical (both resolve a configured
> `upstream_auth_header` if present) — a deliberate backward-compat choice so the migration
> backfill never silently drops a legacy header.

The API rejects `credential_mode='token'` when no signing key is configured.

## Issuer key provisioning

- The signing key is a secret-provider **reference**, never inline material:
  `ACROPOLIS_TOKEN_SIGNING_KEY_REF=vault://kv/cluster/acropolis#token-signing-key`.
- Token signing requires the `encrypted` or `openbao` provider. The `local` provider cannot hold a
  signing key — a PEM literal in Settings is rejected, because it would be readable from
  `/proc/<pid>/environ` (k3s#66).
- The public half is derived; JWKS is served at `/.well-known/jwks.json` (unauthenticated).
- Fail-loud: a configured but unresolvable key aborts startup.

Example (OpenBao + AppRole):

```bash
# Store a 4096-bit key without touching disk.
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 \
  | bao kv put kv/cluster/acropolis token-signing-key=-

# Policy + role for the app. Rotation writes new keys under <base>/keys/<epoch>, hence the
# second path. The provider re-logs-in on lease expiry, so the secret_id is the long-lived
# credential and the tokens stay short-lived.
bao policy write acropolis-token-signing - <<'EOF'
path "kv/data/cluster/acropolis"   { capabilities = ["read", "create", "update"] }
path "kv/data/cluster/acropolis/*" { capabilities = ["read", "create", "update"] }
EOF
bao write auth/approle/role/acropolis-token-signing \
  token_policies=acropolis-token-signing token_ttl=1h token_max_ttl=4h \
  secret_id_ttl=0 token_num_uses=0
```

Deployment env:

```
ACROPOLIS_SECRET_PROVIDER=openbao
ACROPOLIS_VAULT_ADDR=http://openbao.vault-system.svc.cluster.local:8200
ACROPOLIS_VAULT_ROLE_ID=<from the acropolis-vault Secret>
ACROPOLIS_VAULT_SECRET_ID=<from the acropolis-vault Secret>
ACROPOLIS_TOKEN_SIGNING_KEY_REF=vault://kv/cluster/acropolis#token-signing-key
```

## Rotation

`python -m argus rotate-signing-key` is dry-run by default; `--apply` executes:

1. generate a new keypair and store it at `<base>/keys/<epoch>#key`;
2. publish BOTH kids in JWKS;
3. sign with the new key;
4. drop the old kid after 20 minutes (two token TTLs).

The running app re-reads rotation state every few seconds and mutates the issuer in place, so no
restart is needed. Servers cache the JWKS and refetch only on an unknown `kid` — the first
new-key token triggers one refetch per server. Rotation state lives in the `settings` table
(`token_signing_active_ref`, `token_signing_previous_ref`, `token_signing_previous_drop_at`), so
an in-flight overlap survives a restart.

`--apply` exits 0 only after re-resolving the persisted new key and minting a token whose `kid`
matches — i.e. only when the new key is genuinely live and signing.

Drill it before relying on it:

```bash
python -m argus rotate-signing-key --apply
# stream tools/calls through the 20-min overlap -> zero failures;
# the old kid disappears from JWKS at the deadline.
```

## Enabling it on a server

1. Build with the middleware (see the style guide). It is **inert** with no `TOKEN_*` env.
2. Deploy inert; verify a through-gateway call still works with `credential_mode='none'`.
3. Set `TOKEN_JWKS_URL=https://acropolis.krestakos.com/.well-known/jwks.json`,
   `TOKEN_AUDIENCE=<slug>`, `TOKEN_ISSUER=acropolis`.
4. Flip `credential_mode='token'`.
5. Verify: through-gateway works + audit row; direct in-cluster POST → 401; a token minted for a
   different slug → 401; health stays healthy.

For a zero-401 window, flip the mode **before** enabling the env: Acropolis starts sending tokens
to an inert upstream, then the upstream starts requiring the tokens already being sent.

Expect the server to read **unhealthy** with `token auth not enforced: …` in that window (see
"Health: the tokenless check" below). That is the truth: until step 3 is live the upstream is not
refusing anything. The reason clears on the next poll after the env is in, and it fires one
unhealthy webhook on the way in. Do the steps back to back, or expect the alert.

Rollback at any point: set `credential_mode='none'` and remove the `TOKEN_*` env.

## Health: the tokenless check

The authenticated health probe proves a server **accepts** a valid token. It cannot show that the
server would also **refuse** a request with none, and that is the failure that matters:
`mcp-authn` is fail-open on missing config (no `TOKEN_*` env = pass-through, which is how it ships
inert). A redeploy from a manifest that lost the env, or a misspelled variable, turns a protected
server back into an open one while every positive check still passes.

So for every `credential_mode='token'` server that probes healthy, the poller sends one more
request with **no credential at all** (a `ping` to the MCP endpoint, every poll interval) and expects
a refusal:

| Answer | Result |
|---|---|
| `401` or `403` | enforced; server stays healthy |
| any other HTTP status (200, 400, 404, 500 …) | `unhealthy`, reason `token auth not enforced: an unauthenticated request got HTTP <n>, expected 401 …`; one webhook on the edge |
| network error, timeout, or `502`/`503`/`504` | inconclusive; no change (the authenticated probe just succeeded, and those statuses come from something in front of the app, not from the middleware) |

The middleware wraps the whole handler, so a tokenless POST to the MCP endpoint is refused before
routing or body parsing; that is why a 404 or 400 counts as "bypassed". The check never runs for
`none` or `static` servers. It does not stop traffic: `health_status` feeds the metrics, the UI and
the unhealthy webhook, not routing.

## Third-party exceptions

`mcp-grafana` and `workspace-mcp` are upstream images we cannot modify; no middleware can run
inside them. They are enforced by NetworkPolicy alone (k3s#81), permanently, as a documented
exception. Host services (e.g. `mcp-obsidian` on framework-ai) are outside the cluster and are not
covered by NetworkPolicy.
