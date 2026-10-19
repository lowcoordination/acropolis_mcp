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

The signing key lives in OpenBao. Acropolis can log in to OpenBao two ways, both documented in
[secrets.md](secrets.md#authenticating-to-the-secret-server); this page needs only the key and a
policy.

Store the key (4096-bit, without touching disk) and write the policy. Rotation writes each new key
under `<base>/keys/<epoch>`, so the policy must cover the base path **and** `<base>/*`; with only
the base path, the first rotation fails when it tries to store the new key.

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 \
  | bao kv put kv/cluster/acropolis token-signing-key=-

bao policy write acropolis-token-signing - <<'EOF'
path "kv/data/cluster/acropolis"   { capabilities = ["read", "create", "update"] }
path "kv/data/cluster/acropolis/*" { capabilities = ["read", "create", "update"] }
EOF
```

Acropolis logs in as **one** role, so if the same deployment also resolves other secret references
(see [secrets.md](secrets.md)), that role's policies must include the paths for those as well as
the one above; the examples below name a role for the signing key only.

**Kubernetes auth (recommended).** The credential is the pod's own service-account token, which
Kubernetes issues, expires and rotates, so there is no static secret to leak, back up or forget to
rotate. Bind a role to the Acropolis service account. The one-time setup (mounting the method,
`auth/kubernetes/config`) is under "Kubernetes auth" in
[secrets.md](secrets.md#authenticating-to-the-secret-server).

```bash
bao write auth/kubernetes/role/acropolis-token-signing \
  bound_service_account_names=acropolis \
  bound_service_account_namespaces=acropolis \
  policies=acropolis-token-signing ttl=1h
```

Deployment env:

```
ACROPOLIS_SECRET_PROVIDER=openbao
ACROPOLIS_VAULT_ADDR=http://openbao.vault-system.svc.cluster.local:8200
ACROPOLIS_VAULT_AUTH_METHOD=kubernetes
ACROPOLIS_VAULT_K8S_ROLE=acropolis-token-signing
ACROPOLIS_TOKEN_SIGNING_KEY_REF=vault://kv/cluster/acropolis#token-signing-key
```

**AppRole (when Kubernetes auth is not available).** An AppRole `secret_id` is a **long-lived static
credential**: someone has to create it, store it and rotate it by hand, and anyone who copies it can
log in until it is revoked. The provider re-logs-in when its token's lease expires, so the OpenBao
*tokens* stay short-lived, but the `secret_id` does not. Kubernetes auth avoids that credential
entirely, which is why it is the recommended deployment. Prefer the `_FILE` form of the secret_id
over an inline variable (the reasons are in secrets.md).

```bash
bao write auth/approle/role/acropolis-token-signing \
  token_policies=acropolis-token-signing token_ttl=1h token_max_ttl=4h \
  secret_id_ttl=0 token_num_uses=0
```

Deployment env:

```
ACROPOLIS_SECRET_PROVIDER=openbao
ACROPOLIS_VAULT_ADDR=http://openbao.vault-system.svc.cluster.local:8200
ACROPOLIS_VAULT_ROLE_ID=<role id>
ACROPOLIS_VAULT_SECRET_ID_FILE=<path of the mounted secret_id file>
ACROPOLIS_TOKEN_SIGNING_KEY_REF=vault://kv/cluster/acropolis#token-signing-key
```

## Rotation

`python -m argus rotate-signing-key` is dry-run by default; `--apply` executes:

1. generate a new keypair and store it at `<base>/keys/<epoch>#key`;
2. publish BOTH kids in JWKS;
3. sign with the new key;
4. drop the old kid after 20 minutes (two token TTLs).

The running app re-reads rotation state every few seconds and mutates the issuer in place, so no
restart is needed. Servers cache the JWKS and refetch on an unknown `kid` (the first new-key token
triggers one refetch per server) and also once the cached set is older than `TOKEN_JWKS_MAX_AGE`
(see the idle-server drill below). Rotation state lives in the `settings` table
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

### Drill: a server that saw no traffic must drop the old key

The overlap drill above proves servers *gain* the new key. It does not prove the other half: that a
server which saw **no traffic** during the overlap stops trusting the old key afterwards. A server
that only refetches on an unknown `kid` never would: nothing it receives carries a new `kid`, so it
keeps the old key for as long as it runs. `mcp-authn` therefore also refetches the JWKS once its
cached key set is older than `TOKEN_JWKS_MAX_AGE` (default 10 minutes; accepted range 30 seconds to
24 hours). Run this drill once after any `mcp-authn` upgrade and after changing that variable.

The refetch is **driven by request traffic**: the age of the cache is checked when a request
arrives. In a running fleet, Acropolis's own health probes
(about one a minute per server) are that traffic, so every token-mode server refetches roughly every
`TOKEN_JWKS_MAX_AGE`, whether or not any client uses it.

1. Rotate, and note the two references the command prints (`previous key <ref>` and
   `active key <ref>`):

   ```bash
   python -m argus rotate-signing-key --apply
   ```

2. Wait until the old key has been dropped from JWKS (20 minutes) **plus more than
   `TOKEN_JWKS_MAX_AGE`** (10 minutes by default): at least 32 minutes after step 1. Every server's
   cached key set is then either newly fetched without the old key or old enough to be refetched on
   the next request. Do not send any request signed with the old key before this point; the drill is
   only meaningful if the cache aged out by itself.

3. Confirm the old `kid` is gone from the public JWKS (`https://acropolis.example.com/.well-known/jwks.json`
   lists only the active key's `kid`). Then send a token signed by the **old** key to a server, and
   one signed by the **new** key as a control. Save this probe as `rotation-drill-probe.py`. It runs
   inside the Acropolis pod, reads the key at `KEY_REF` back from the secret store (so no key
   material reaches your machine), mints a token for the audience `SLUG`, POSTs a `ping` to
   `SERVER_URL` and prints only the HTTP status. The token lives 10 minutes and is never printed.

   ```python
   import asyncio
   import os

   import httpx

   from archon.secrets import build_secret_provider
   from archon.settings import Settings
   from argus.tokens import TokenIssuer, _resolve_rsa_private_key


   async def main() -> None:
       provider = build_secret_provider(Settings())
       key = await _resolve_rsa_private_key(os.environ["KEY_REF"], provider)
       token = TokenIssuer(key).mint_uncached(os.environ["SLUG"])
       headers = {
           "Authorization": f"Bearer {token}",
           "Content-Type": "application/json",
           "Accept": "application/json, text/event-stream",
           "Mcp-Method": "ping",
       }
       body = {"jsonrpc": "2.0", "id": "rotation-drill", "method": "ping"}
       async with httpx.AsyncClient(trust_env=False, timeout=10, follow_redirects=False) as client:
           response = await client.post(os.environ["SERVER_URL"], headers=headers, json=body)
       print(f"HTTP {response.status_code}")


   asyncio.run(main())
   ```

   ```bash
   # SLUG is the server's audience (its slug); SERVER_URL is its registered URL, exactly as stored.
   # Keep the quotes: an unquoted URL containing & ; or $( ) is split or expanded by your shell.
   for ref in "<previous key ref>" "<active key ref>"; do
     kubectl exec -i deploy/acropolis -- env KEY_REF="$ref" SLUG="<slug>" SERVER_URL="<registered url>" \
       python - < rotation-drill-probe.py
   done
   ```

   The second run sends a token that is **valid for 10 minutes** for that audience, so point
   `SERVER_URL` only at the server's own registered URL; a token sent anywhere else can be replayed
   against that server until it expires.

**Expected result.**

| Probe | Result | Meaning |
|---|---|---|
| signed by the **previous** key | `HTTP 401` | the server dropped the old key |
| signed by the **active** key | `HTTP 200` | control: URL, audience and path are right, so the 401 above is about the key and not a typo |

`HTTP 200` for the previous key is a failed drill: that server still trusts a key Acropolis
stopped publishing. Check that its `mcp-authn` is v0.2.0 or later and that `TOKEN_JWKS_MAX_AGE` is
not set to hours. If the control is not `200`, the probe is wrong (audience, URL, a gateway in
between); fix it before reading anything into the first line.

**Confirm the refetch itself in the Acropolis logs.** The JWKS route is served by Acropolis, so
every server's refetch appears there:

```bash
kubectl logs deploy/acropolis | grep -c 'GET /.well-known/jwks.json'
kubectl logs deploy/acropolis --since=1h | grep -c 'GET /.well-known/jwks.json'   # per hour
```

In a healthy fleet that is about **6 fetches per server per hour** (one per 10-minute max age),
arriving in staggered bursts every 10 minutes as the servers' caches age out together. A fleet of
ten servers measured in production gave about 59 per hour. The rate is `3600 / TOKEN_JWKS_MAX_AGE`
(in seconds) per server, so it changes if you set the variable. Read it over a quiet hour: boots and
the rotation itself add fetches (each server refetches once on the first new-`kid` token).

**A count of zero** (over a window longer than the max age, with the health poller running) means
no server is refetching: its cache never ages out, so a key dropped from JWKS **stays trusted** by
that server. Likely causes are an `mcp-authn` older than v0.2.0, a wrong `TOKEN_JWKS_URL`, or the
health poller being disabled and no other traffic arriving. A count well below
`servers x 6` means some servers are not refetching.

What the drill does **not** isolate: while the health poller runs, every server gets a request a
minute from Acropolis, so no registered server is ever truly traffic-free, and the status codes alone
cannot tell a refetch caused by a health probe from one caused by the drill's own request. That is
the deployment's real condition, and the log count is the evidence that refetching happens without
any client traffic.

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
"Health: the enforcement checks" below). That is the truth: until step 3 is live the upstream is not
refusing anything. The reason clears on the next poll after the env is in, and it fires one
unhealthy webhook on the way in. Do the steps back to back, or expect the alert.

Rollback at any point: set `credential_mode='none'` and remove the `TOKEN_*` env.

## Health: the enforcement checks

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

### The wrong-audience check

A server that refuses a missing token but accepts **any** bearer string passes the tokenless check.
So when (and only when) the tokenless request was conclusively refused, the poller sends one more
`ping`: a token that is correctly signed by this Acropolis's issuer but for an audience no server
accepts (random, per request, never a real slug). A server that verifies signature and audience
refuses it; one that does not, accepts it.

| Answer | Result |
|---|---|
| `401` or `403` | audience enforced; server stays healthy |
| any other HTTP status (200, 400, 404, 500 …) | `unhealthy`, reason `token accepted for the wrong audience: a token signed for a different audience got HTTP <n>, expected 401 …`; one webhook on the edge |
| network error, timeout, or `502`/`503`/`504` | inconclusive; no change |

Cost and safety:

- **One extra request per token-mode server per poll**, and none when the tokenless check failed or
  was inconclusive (the server is already unhealthy, or already flaky). The checks run inside the
  server's own probe slot and servers are probed concurrently, so a stalled server delays only
  itself. Each request has its own 10 s overall deadline, so a server that answers the tokenless
  request promptly and then stalls the audience one holds its slot at most 10 s longer.
- Both checks share one request path: a fresh HTTP client (so the poller's cookie jar cannot add a
  credential), `trust_env=False` (no proxy or `.netrc` from the environment), redirects reported and
  never followed (a followed redirect would hand the token to another host), the response streamed
  and only the status line read, under the overall deadline.
- The probe token is minted for that one request (`TokenIssuer.mint_uncached`, so it never enters
  the per-slug cache that real requests draw from) and exists only in the request headers. It is not
  logged, stored or put in `health_reason`.

What the two checks together still do **not** prove: that the server rejects a token with a *valid*
audience signed by a *different key*. That needs a third request; alternating the two token kinds
per poll would make a server that fails only one of them flap between healthy and unhealthy, so it
is left out. They also test only the registered URL, and an upstream that has been compromised can
simply answer 401.

## Third-party exceptions

`mcp-grafana` and `workspace-mcp` are upstream images we cannot modify; no middleware can run
inside them. They are enforced by NetworkPolicy alone (k3s#81), permanently, as a documented
exception. Host services (e.g. `mcp-obsidian` on framework-ai) are outside the cluster and are not
covered by NetworkPolicy.
