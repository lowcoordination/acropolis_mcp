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

1. `ACROPOLIS_SECRET_KEYS` — a key **ring**: comma-separated key materials (each 64 hex chars
   or standard base64). The **first** key is the *active* key, used for all new encryptions;
   the remaining keys are decryption-only. This is the rotation form.
2. `ACROPOLIS_SECRET_KEYS_FILE` — a file containing the same ring, one key material per line
   (blank lines ignored); the first non-blank line is the active key.
3. `ACROPOLIS_SECRET_KEY` — the original single key, unchanged: equivalent to a one-key ring.
4. `ACROPOLIS_SECRET_KEY_FILE` — the original single-key file, unchanged.

Setting both a plural and a singular form is a configuration error (ambiguous intent). One of
the four is required when `encrypted` is selected; there is no default key. Generate keys with:

```bash
openssl rand -hex 32
```

The `v1` version prefix means the ciphertext format can change later (a different AEAD, a
different KDF, a wrapped-DEK/KMS scheme) without breaking data already encrypted under `v1` — a
future provider version dispatches on the prefix and can still decrypt old data.

> [!WARNING] Threat model — read this before trusting this tier for anything
>
> **This defends backup and snapshot leakage**: a stolen copy of the database, a leaked
> `pg_dump` / volume snapshot that ends up somewhere it shouldn't. Without the key — which is
> never itself stored in the database — the ciphertext in `upstream_auth_header` is useless.
>
> **This does NOT defend a live host compromise.** If an attacker has code execution on the
> running Acropolis process, or read access to wherever `ACROPOLIS_SECRET_KEY[_FILE]` /
> `ACROPOLIS_SECRET_KEYS[_FILE]` is configured (an env var, a mounted file, a compose/k8s
> secret), they can decrypt everything the application can decrypt — the same way the
> application itself does on every call. That is not a bug to fix later; it's what "the app
> needs the plaintext to authenticate outbound calls" necessarily means for any software
> running as one process. The key ring does not change this boundary: every key in the ring is
> exactly as powerful as every other, and stays fully live until removed after re-encryption.
>
> **A key file sitting in the same volume as the database provides zero real protection.** It
> defeats the entire point of this tier: an attacker (or a backup) that gets the database gets
> the key sitting right next to it. Put the key somewhere the database backup doesn't reach — a
> separate secret store, a different volume, an env var injected only into the running
> container/pod and never persisted to disk alongside the data directory.
>
> Overclaiming what `encrypted` buys you is worse than not building it. State the boundary
> plainly: this is AES-GCM-with-an-external-key, defending the realistic homelab threat of a
> leaked backup — not a substitute for host security.

### Rotating the key

Rotation is the key ring's reason to exist. The whole sequence, in order:

```bash
# 1. Generate the new key (keep the old one — you still need it for this step)
NEW=$(openssl rand -hex 32)

# 2. Deploy with BOTH keys: new key FIRST (active), old key second (decryption-only).
#    Example compose/k8s env:
#      ACROPOLIS_SECRET_KEYS="$NEW,$OLD"
#    The app keeps working the entire time: existing enc:v1: ciphertext still resolves
#    (old key is in the ring), new writes go under the new key.
#    (If you use ACROPOLIS_SECRET_KEYS_FILE instead: new key on the first line, old key
#    on the second.)

# 3. Re-encrypt every stored credential under the new active key (dry run first):
argus reencrypt                 # preview: what WOULD be re-encrypted
argus reencrypt --apply         # actually rewrite, exit 0 = all succeeded

# 4. Deploy with ONLY the new key:
#      ACROPOLIS_SECRET_KEYS="$NEW"
#    (or ACROPOLIS_SECRET_KEY="$NEW"). The old key is now gone from the process.

# 5. Confirm rotation is complete — every enc:v1: credential must resolve under the new key
#    alone. `argus reencrypt --apply` failing with a nonzero exit in step 3 already tells you
#    which server(s) still hold ciphertext the ring can't decrypt.
```

What each step guards against:

- **Deploying the new key alone first (skipping step 2) would brick every stored credential** —
  construction only validates key *length*, so the app starts fine and fails later, per-server,
  at the next outbound call. The ring exists so rotation has no downtime window where
  credentials are undecryptable.
- **Skipping step 3 (re-encryption) means the old key stays live forever** — the ring does not
  shrink a key's power; it only lets old ciphertext keep resolving during rotation. Drop the
  old key only after re-encryption reports every credential rewritten.
- **`argus reencrypt` requires the encrypted tier's key material** (any of the four env forms);
  without it the command fails at construction with a clear error rather than doing nothing.
  Literal credentials and `vault://` references are skipped — they are not this tier's format.

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
| `VAULT_TOKEN` | one auth method (see below) | Static token auth |
| `VAULT_ROLE_ID` + `VAULT_SECRET_ID` or `VAULT_SECRET_ID_FILE` | | AppRole auth (logs in, caches the resulting token for its lease) |
| `VAULT_AUTH_METHOD` = `kubernetes` + `VAULT_K8S_ROLE` | | Kubernetes auth (no static secret at all) |
| `VAULT_K8S_TOKEN_FILE` | no (default `/var/run/secrets/kubernetes.io/serviceaccount/token`) | Where the pod's service-account token is read from |
| `VAULT_K8S_MOUNT` | no (default `kubernetes`) | Name the Kubernetes auth method is mounted under |
| `VAULT_TTL_SECONDS` | no (default 60) | Resolved-value cache TTL — see below |

#### Authenticating to the secret server

Pick exactly one. Leave `VAULT_AUTH_METHOD` unset and the method is inferred exactly as before
(a token if one is set, otherwise AppRole), so an existing deployment does not change. Kubernetes
auth is **never** inferred: it must be selected, so a stray variable cannot change how you log in.
Giving credentials for more than one method, or half of one, is a startup error, not a surprise at
first use. None of this ties Acropolis to a platform: the client only makes HTTP requests and
reads files.

**Static token.** `VAULT_TOKEN`. Simple; the token is long-lived unless you issue it with a TTL.

**AppRole.** `VAULT_ROLE_ID` plus the secret_id, given either inline (`VAULT_SECRET_ID`) or as a
**file** (`VAULT_SECRET_ID_FILE`, not both). Prefer the file: an environment variable is readable
through `/proc/<pid>/environ` by any process running as the same user and through
`docker inspect`, while a mounted file is not in either place. The file is re-read on every
login, so replacing it rotates the credential without a restart. Trailing newlines are stripped.
Docker Compose:

```yaml
services:
  acropolis:
    environment:
      ACROPOLIS_SECRET_PROVIDER: openbao
      ACROPOLIS_VAULT_ADDR: https://vault.example.internal:8200
      ACROPOLIS_VAULT_ROLE_ID: 11111111-2222-3333-4444-555555555555   # an id, not a secret
      ACROPOLIS_VAULT_SECRET_ID_FILE: /run/secrets/vault_secret_id
    secrets:
      - vault_secret_id
secrets:
  vault_secret_id:
    file: ./vault_secret_id          # chmod 600, not committed
```

**Kubernetes auth.** The credential is the pod's own service-account token, which Kubernetes
issues, expires and rotates. No static secret exists to leak, back up or forget to rotate, and
deleting the pod, the service account or the OpenBao role cuts access. The pod posts that token and
a role name to `auth/<mount>/login`; OpenBao has the Kubernetes API validate it (the TokenReview
API) and checks the role's bindings, then returns a normal token. Acropolis re-reads the token file
on every login because kubelet rewrites a projected token in place.

OpenBao side (once; a live change, run by an operator; see the
[OpenBao Kubernetes auth docs](https://openbao.org/docs/auth/kubernetes/) for your version):

```bash
bao auth enable kubernetes                       # skip if already mounted
# Run from inside the OpenBao pod, which then uses its own pod token to ask Kubernetes to
# validate logins (the OpenBao docs' recommended setup when OpenBao runs in the cluster):
bao write auth/kubernetes/config \
    kubernetes_host=https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT
bao policy write acropolis - <<'EOF'
path "secret/data/acropolis/*" { capabilities = ["read"] }
EOF
bao write auth/kubernetes/role/acropolis \
    bound_service_account_names=acropolis \
    bound_service_account_namespaces=acropolis \
    policies=acropolis ttl=1h
```

`read` is all Acropolis needs to resolve references. Add `create` and `update` only if you use
`python -m argus rotate-signing-key`, which writes each new signing key to its own path under the
current key's path, so the policy must cover that prefix too.

Pod side:

```yaml
spec:
  serviceAccountName: acropolis
  containers:
    - name: acropolis
      env:
        - {name: ACROPOLIS_SECRET_PROVIDER,    value: openbao}
        - {name: ACROPOLIS_VAULT_ADDR,         value: "http://openbao.vault-system.svc:8200"}
        - {name: ACROPOLIS_VAULT_AUTH_METHOD,  value: kubernetes}
        - {name: ACROPOLIS_VAULT_K8S_ROLE,     value: acropolis}
```

The default token path is the standard in-cluster one, so no volume is required. To bound its
lifetime explicitly, project a token instead and point `ACROPOLIS_VAULT_K8S_TOKEN_FILE` at it
(`serviceAccountToken` volume with a short `expirationSeconds`). Do not set a custom `audience` on
the projected token unless you also set the matching `audience` on the OpenBao role; that pairing
is not exercised by this project's tests.

What Kubernetes auth does **not** do: it does not stop anyone who can create tokens for the
service account (`kubectl create token`) or read the pod's filesystem as the same user. It removes
the long-lived static credential and the places a copy of it ends up; it is not a substitute for
controlling who is cluster-admin.

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
