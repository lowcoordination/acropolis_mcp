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

Rollback at any point: set `credential_mode='none'` and remove the `TOKEN_*` env.

## Third-party exceptions

`mcp-grafana` and `workspace-mcp` are upstream images we cannot modify; no middleware can run
inside them. They are enforced by NetworkPolicy alone (k3s#81), permanently, as a documented
exception. Host services (e.g. `mcp-obsidian` on framework-ai) are outside the cluster and are not
covered by NetworkPolicy.
