from __future__ import annotations

import asyncio
import json
import logging
from secrets import token_hex
from typing import Optional

import httpx

from archon.background import BackgroundLoop
from archon.secrets import SecretProvider
from archon.secrets.local import LocalSecretProvider
from argus.bridge import META_CLIENT_CAPABILITIES, META_CLIENT_INFO, META_PROTOCOL_VERSION
from argus.credentials import (
    TOKEN_MINT_FAILED,
    TOKEN_NOT_CONFIGURED,
    UpstreamCredentialError,
    resolve_upstream_credential,
)
from argus.headers import MCP_METHOD_HEADER
from argus.tokens import TokenIssuer
from argus.upstream import (
    CLIENT_INFO,
    MCP_2026_VERSION,
    ResponseRejected,
    UpstreamHandshakeCache,
    UpstreamHandshakeError,
    UpstreamHandshakeTimeout,
    UpstreamHandshakeTooLarge,
    bounded_post,
    parse_sse_body,
)
from db.models import ServerRecord
from db.repo import ServerNotFoundError, ServerRepo
from stoa.webhooks import WebhookDispatcher

logger = logging.getLogger("stoa.health")

DEFAULT_POLL_INTERVAL_SECONDS = 60.0
# Health probes must never block on the shared http client's generous default timeout (120s,
# sized for real tool calls) — a routine check against a briefly-unreachable or restarting
# upstream should fail fast, not stall the whole poll cycle for every other registered server.
PROBE_TIMEOUT_SECONDS = 10.0
# httpx's timeout applies to each I/O operation, not to the exchange: an upstream that sends one
# byte every few seconds never trips it. So PROBE_TIMEOUT_SECONDS is ALSO enforced as an overall
# deadline on each probe HTTP exchange (see argus.upstream.bounded_post), and the probe as a whole
# (discover + initialize fallback + secret/token resolution) gets PROBE_DEADLINE_SECONDS. Both are
# module-level so a test can shrink them.
PROBE_DEADLINE_SECONDS = 30.0
# A server/discover or initialize result is small. This bounds what one hostile upstream can make
# us buffer per probe (a 64 MiB body was observed to cost ~130 MiB RSS with the buffering client).
PROBE_MAX_RESPONSE_BYTES = 1024 * 1024
# How many servers are probed at once. Probes are independent, so one slow server must not delay the
# rest; the bound keeps a large fleet from opening hundreds of sockets in a single burst.
MAX_CONCURRENT_PROBES = 16

# Issue #134 (T3): the reason prefix when a token-mode probe can't mint its JWT — distinguishable
# from a plain network failure (health_reason None) and from a secret-resolution failure.
TOKEN_MINT_FAILURE_PREFIX = "token mint failed: "

# Issue #134 hardening: the reason prefix when a token-mode server ANSWERS a request that carries
# no credential. See check_auth_enforced.
AUTH_NOT_ENFORCED_PREFIX = "token auth not enforced: "

# Issue #156: the reason prefix when a token-mode server REFUSES a request with no token but ACCEPTS a
# genuinely signed token whose audience is not its own. See check_auth_enforced.
AUDIENCE_NOT_ENFORCED_PREFIX = "token accepted for the wrong audience: "

# Reasons for a probe that was cut off rather than answered (see PROBE_DEADLINE_SECONDS and
# PROBE_MAX_RESPONSE_BYTES): distinguishable from a plain outage (health_reason None).
PROBE_TIMEOUT_PREFIX = "probe timed out: "
PROBE_RESPONSE_REJECTED_PREFIX = "probe response rejected: "


async def probe_server(
    client: httpx.AsyncClient, handshake_cache: UpstreamHandshakeCache, server: ServerRecord,
    secret_provider: SecretProvider | None = None,
    token_issuer: TokenIssuer | None = None,
) -> tuple[str, str | None, dict | None, str | None]:
    """Probe one server's generation and health.

    Tries `server/discover` first (mandatory RPC for 2026-generation servers per the spec);
    on method-not-found, falls back to the 2025-generation `initialize` handshake. Returns
    (health_status, upstream_protocol, discover_json_dict, health_reason).

    `health_reason` is None for a normal healthy probe AND for a normal (network-level)
    unhealthy probe — it is only set when the specific cause was a secret-resolution failure
    (enterprise #5), a token-mint failure, or a response that was cut off (overall deadline or
    byte cap exceeded), so such a server reads unhealthy with a reason distinguishable from
    "upstream is just down", rather than a generic/opaque failure.
    Callers (HealthPoller) must not guess a reason from health_status alone; this is the one
    source of truth for whether THIS was a secrets problem.
    """
    secrets = secret_provider or LocalSecretProvider()
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        # Advertise the modern era so 2026-generation upstreams answer `server/discover`
        # directly; 2025-generation upstreams ignore/4xx it and use the initialize fallback.
        "MCP-Protocol-Version": MCP_2026_VERSION,
        # 2026 spec: the modern transport validates that the request's method appears in
        # both the body and this header (HEADER_MISMATCH otherwise). The canonical constant
        # (not a lowercase literal) matters: a strict upstream comparing header NAMES
        # literally — as argus/headers.py's own header_matches_body() convention implies —
        # would reject the probe.
        MCP_METHOD_HEADER: "server/discover",
    }
    # A server with a configured upstream credential needs it on the health probe too, or every
    # registered server requiring auth would show permanently unhealthy regardless of whether
    # tools/call itself works. A token-mode server needs its JWT for the same reason: a probe that
    # 401s while tools/call works would read permanently unhealthy.
    #
    # The per-mode rule is argus.credentials.resolve_upstream_credential (issue #155), shared with
    # the data plane and the control plane; this only maps its failure to an unhealthy reason. A
    # failure must NEVER be treated the same as "no credential configured" (which would probe
    # unauthenticated and either misreport health or, worse, look healthy against an upstream that
    # doesn't actually need auth), so it is reported as its own distinguishable reason.
    try:
        resolved_auth_header = await resolve_upstream_credential(
            server, secrets=secrets, token_issuer=token_issuer,
        )
    except UpstreamCredentialError as e:
        if e.kind == TOKEN_NOT_CONFIGURED:
            return ("unhealthy", None, None, f"{TOKEN_MINT_FAILURE_PREFIX}token signing is not configured")
        if e.kind == TOKEN_MINT_FAILED:
            return ("unhealthy", None, None, f"{TOKEN_MINT_FAILURE_PREFIX}token mint failed")
        logger.info("probe for '%s' could not resolve its credential: %s", server.slug, e.reason)
        # e.reason already reads "secret resolution failed: <reason>".
        return ("unhealthy", None, None, e.reason)
    if resolved_auth_header:
        headers["Authorization"] = resolved_auth_header
    discover_body = {
        "jsonrpc": "2.0", "id": "acropolis-discover", "method": "server/discover",
        # Modern (2026-07-28) discovery: per the spec the request carries NO body parameters
        # beyond the standard `_meta` envelope — protocolVersion, clientInfo, and
        # clientCapabilities — alongside the matching `MCP-Protocol-Version` and `Mcp-Method`
        # headers. (clientInfo lives INSIDE _meta as io.modelcontextprotocol/clientInfo, NOT
        # at params top level — a strict 2026 server won't find it there.) 2025-generation
        # upstreams answer this with a method-not-found error and fall through to the
        # initialize handshake below.
        "params": {
            "_meta": {
                META_PROTOCOL_VERSION: MCP_2026_VERSION,
                META_CLIENT_INFO: CLIENT_INFO,
                META_CLIENT_CAPABILITIES: {},
            },
        },
    }

    try:
        resp = await bounded_post(
            client, server.upstream_url, json=discover_body, headers=headers,
            max_bytes=PROBE_MAX_RESPONSE_BYTES, deadline=PROBE_TIMEOUT_SECONDS,
        )
    except asyncio.TimeoutError:
        logger.info("probe for '%s' did not finish within %ss", server.slug, PROBE_TIMEOUT_SECONDS)
        return ("unhealthy", None, None, f"{PROBE_TIMEOUT_PREFIX}no complete response within {PROBE_TIMEOUT_SECONDS:g}s")
    except ResponseRejected as e:
        logger.info("probe for '%s' response rejected: %s", server.slug, e)
        return ("unhealthy", None, None, f"{PROBE_RESPONSE_REJECTED_PREFIX}{e}")
    except httpx.HTTPError as e:
        logger.info("probe for '%s' failed to connect: %s", server.slug, e)
        return ("unhealthy", None, None, None)

    if resp.status_code == 200:
        # This parse MUST stay guarded: a 200 response with a non-JSON body (e.g. an auth
        # proxy's HTML login page in front of a misconfigured upstream) otherwise raises
        # JSONDecodeError that escapes probe_server -> _probe_and_store -> poll_once, and one
        # bad server aborts the whole poll cycle — leaving every server after it in slug order
        # with permanently stale health.
        try:
            parsed = (
                parse_sse_body(resp.text)
                if "text/event-stream" in resp.headers.get("content-type", "")
                else (json.loads(resp.text) if resp.text else None)
            )
        except (json.JSONDecodeError, ValueError, RecursionError) as e:
            logger.info("probe for '%s' returned an unparseable 200 response: %s", server.slug, e)
            parsed = None

        if parsed and "result" in parsed:
            # A real server/discover response — this is a 2026-generation server.
            return ("healthy", "2026-07-28", parsed["result"], None)
        # `(parsed.get("error") or {})`, not `parsed.get("error", {})`: dict.get's default only
        # applies when the KEY is absent, not when its value is explicitly null, and an upstream
        # may legitimately send `"error": null`. The `or` is correct here precisely because the
        # only falsy value this can take is one we want replaced.
        error_message = (parsed.get("error") or {}).get("message", "") if parsed else ""
        if "method" in error_message.lower():
            # Method-not-found-shaped error — fall through to the 2025 handshake below.
            pass

    # Either server/discover isn't implemented (2025-generation) or the probe didn't return a
    # clean result — fall back to a real initialize handshake, which every 2025 upstream must
    # support and which also confirms the server is actually reachable and speaking MCP.
    try:
        handshake = await handshake_cache.get_or_handshake(
            server.id, server.upstream_url, timeout=PROBE_TIMEOUT_SECONDS,
            upstream_auth_header=resolved_auth_header,
        )
    except UpstreamHandshakeTimeout as e:
        logger.info("probe for '%s' failed initialize fallback: %s", server.slug, e)
        return ("unhealthy", None, None, f"{PROBE_TIMEOUT_PREFIX}no complete response within {PROBE_TIMEOUT_SECONDS:g}s")
    except UpstreamHandshakeTooLarge as e:
        logger.info("probe for '%s' failed initialize fallback: %s", server.slug, e)
        return ("unhealthy", None, None, f"{PROBE_RESPONSE_REJECTED_PREFIX}{e}")
    except UpstreamHandshakeError as e:
        logger.info("probe for '%s' failed initialize fallback: %s", server.slug, e)
        return ("unhealthy", None, None, None)

    discover_json = {
        "protocolVersion": handshake.protocol_version,
        "serverInfo": handshake.server_info,
        "capabilities": handshake.capabilities,
    }
    return ("healthy", handshake.protocol_version, discover_json, None)


# Hard ceiling on the WHOLE of each enforcement request (tokenless, wrong-audience). httpx's timeout
# applies to each I/O operation, not to the request, so an upstream that drips bytes just inside it
# (1 byte every few seconds) would otherwise hold this call open for minutes, occupying one of the
# poller's probe slots. Module-level so a test can shrink it.
AUTH_CHECK_DEADLINE_SECONDS = PROBE_TIMEOUT_SECONDS

# Statuses that mean "refused by the auth gate".
_REFUSED = (401, 403)
# Gateway-class statuses come from something IN FRONT of the app (an ingress or proxy mid rollout, a
# restarting pod's Service), never from the middleware, which answers 401 before the application can
# run. They say nothing about auth, so they are the same transient as a dropped connection.
_GATEWAY_TRANSIENT = (502, 503, 504)


async def _status_only_post(url: str, headers: dict, body: dict) -> int:
    """POST and return only the status code. The one request path for every enforcement check.

    A fresh client on purpose, not the app's shared one: the shared client has a cookie jar, so a
    session cookie an upstream set on an earlier AUTHENTICATED response would ride along on a
    request that is meant to carry only what ``headers`` says (observed in the PR #150 security
    scan). ``trust_env=False`` keeps ``.netrc`` credentials and proxy environment variables out of it
    too, and ``follow_redirects=False`` means a 3xx is reported as the answer rather than chased to
    another host (which would also be sent the Authorization header). Streamed, and the body is never
    read: only the status line matters, and buffering would let a hostile upstream make us hold an
    arbitrarily large body per probe."""
    async with httpx.AsyncClient(
        timeout=PROBE_TIMEOUT_SECONDS, follow_redirects=False, trust_env=False,
    ) as client:
        async with client.stream("POST", url, json=body, headers=headers) as resp:
            return resp.status_code


async def _enforcement_status(server: ServerRecord, headers: dict, body: dict, what: str) -> Optional[int]:
    """The status ``server`` answered an enforcement request with, or ``None`` when the answer is
    inconclusive: a network error, a timeout past AUTH_CHECK_DEADLINE_SECONDS, or a gateway-class
    502/503/504. The authenticated probe just succeeded, so each of those is a transient, and a
    transient must not raise a security alert. ``what`` names the check in the log line only; never
    pass anything derived from ``headers`` (it may carry a token)."""
    try:
        status = await asyncio.wait_for(
            _status_only_post(server.upstream_url, headers, body), timeout=AUTH_CHECK_DEADLINE_SECONDS,
        )
    except (httpx.HTTPError, asyncio.TimeoutError) as e:
        logger.info(
            "%s check for '%s' was inconclusive: %s", what, server.slug, e or type(e).__name__,
        )
        return None
    if status in _GATEWAY_TRANSIENT:
        logger.info("%s check for '%s' was inconclusive: HTTP %s", what, server.slug, status)
        return None
    return status


def _probe_audience() -> str:
    """An audience no server accepts: random, so it can never collide with a real slug (a server's
    audience IS its slug) and a server cannot be configured to accept it by accident."""
    return f"acropolis-health-probe-{token_hex(8)}"


async def check_auth_enforced(
    server: ServerRecord, token_issuer: Optional[TokenIssuer] = None,
) -> Optional[str]:
    """Negative probes for a ``credential_mode='token'`` server. Returns ``None`` when the server
    behaved (or the answer is inconclusive), else a reason string to store as ``health_reason``.

    1. TOKENLESS. Send a request with NO credential and require 401/403. The authenticated probe
       only proves the server accepts a valid token — it says nothing about whether the server
       would also accept no token. That is the failure that matters here, and mcp-authn is
       deliberately fail-open on missing config (no ``TOKEN_*`` env = pass-through, so it can ship
       inert): a redeploy from a manifest that lost the env, or a typo'd variable name, silently
       turns a protected server back into an open one, and every positive check keeps passing. The
       middleware wraps the whole handler, so an unauthenticated POST to the MCP endpoint is refused
       BEFORE routing or body parsing; a 200, a 404 or a 400 all mean the request got past the gate.

    2. WRONG AUDIENCE (issue #156; only when ``token_issuer`` is given and step 1 CONCLUSIVELY saw a
       refusal). A server that refuses a missing token but accepts any well-formed bearer string
       passes step 1. So send a token that is correctly signed by this Acropolis's issuer but for an
       audience no server accepts, and require 401/403 again. A 200 means the server is not
       checking the audience (or the signature). This costs one extra request per token-mode server
       per poll, and none when step 1 failed or was inconclusive. The token is minted for this one
       request (``TokenIssuer.mint_uncached``: not cached, so a real request is never handed it),
       exists only in the request headers, and is never logged, stored or put in the returned
       reason.

    "Inconclusive" (network error, timeout, or a gateway-class 502/503/504) returns ``None`` for
    both steps, because a transient must not raise a security alert.

    What this does NOT prove: that the server rejects a token with a valid audience signed by a
    different key (that would be a second request; alternating the two per poll would make a
    non-conforming server flap between healthy and unhealthy). It also only tests the registered
    URL, and a compromised upstream can simply answer 401. It closes specific blind spots (auth
    silently switched off, audience or signature unchecked), not the whole class.

    ``ping`` is a no-side-effect MCP method. Step 1 sends nothing that could authenticate: no
    Authorization header, no token, no cookie."""
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        MCP_METHOD_HEADER: "ping",
    }
    body = {"jsonrpc": "2.0", "id": "acropolis-auth-check", "method": "ping"}
    status = await _enforcement_status(server, headers, body, "auth-enforcement")
    if status is None:
        return None
    if status not in _REFUSED:
        logger.warning(
            "server '%s' is in token mode but answered an unauthenticated request with HTTP %s",
            server.slug, status,
        )
        return (
            f"{AUTH_NOT_ENFORCED_PREFIX}an unauthenticated request got HTTP {status}, "
            "expected 401 — it was not refused by token auth"
        )
    if token_issuer is None:
        return None

    try:
        probe_token = token_issuer.mint_uncached(_probe_audience())
    except Exception:
        # The real token minted a moment ago, so this should not fail; if it does it is not evidence
        # about the server. Log the traceback only: the exception is from a signing call and does
        # not carry the token (none exists yet).
        logger.exception("wrong-audience probe for '%s' could not mint its token", server.slug)
        return None
    status = await _enforcement_status(
        server, {**headers, "Authorization": f"Bearer {probe_token}"},
        {**body, "id": "acropolis-audience-check"}, "wrong-audience",
    )
    if status is None or status in _REFUSED:
        return None
    logger.warning(
        "server '%s' is in token mode but accepted a token for the wrong audience (HTTP %s)",
        server.slug, status,
    )
    return (
        f"{AUDIENCE_NOT_ENFORCED_PREFIX}a token signed for a different audience got HTTP {status}, "
        "expected 401 — the server is not verifying the token's audience"
    )


class HealthPoller(BackgroundLoop):
    """Background task: periodically probes every enabled server and updates its health/
    protocol/discover_json fields via ServerRepo.set_health()."""

    _log_name = "health poller task"
    _logger = logger

    def __init__(
        self,
        server_repo: ServerRepo,
        client: httpx.AsyncClient,
        handshake_cache: UpstreamHandshakeCache,
        interval_seconds: float = DEFAULT_POLL_INTERVAL_SECONDS,
        webhook_dispatcher: Optional[WebhookDispatcher] = None,
        secret_provider: Optional[SecretProvider] = None,
        token_issuer: Optional[TokenIssuer] = None,
    ):
        super().__init__()
        self._repo = server_repo
        self._client = client
        self._handshakes = handshake_cache
        self._interval = interval_seconds
        self._webhooks = webhook_dispatcher
        # Defaults to LocalSecretProvider (pass-through) — see Pipeline's identical default and
        # rationale; app.py wires the real, settings-selected provider.
        self._secrets = secret_provider or LocalSecretProvider()
        # Issue #134 (T3): the JWT issuer, wired by argus/app.py's lifespan after construction
        # (same two-phase shape as Pipeline — see Pipeline.set_token_issuer). None = token mode
        # unavailable, so token-mode probes fail closed (unhealthy) rather than probe bare.
        self._token_issuer = token_issuer

    def set_token_issuer(self, issuer: Optional[TokenIssuer]) -> None:
        """Wire the issuer constructed at startup (argus/app.py's lifespan). None = token mode
        unavailable — probe_server then reports token-mode servers unhealthy rather than probing
        them unauthenticated."""
        self._token_issuer = issuer

    async def poll_once(self) -> None:
        # Each _probe_and_store is wrapped individually so an exception in EITHER the probe or
        # the set_health() write for one server can never abort the whole cycle and leave every
        # server after it in slug order permanently stale. Defense in depth on top of the
        # guarded parse above, not a substitute for it.
        #
        # Servers are probed CONCURRENTLY (bounded by a semaphore), each under its own deadline
        # (see _probe_and_store). Serial probing meant one slow server delayed every server after
        # it in slug order by however long it took to give up.
        servers = await self._repo.list()
        gate = asyncio.Semaphore(MAX_CONCURRENT_PROBES)

        async def _one(server: ServerRecord) -> None:
            async with gate:
                try:
                    await self._probe_and_store(server)
                except Exception:
                    logger.exception("health probe failed for server '%s'", server.slug)

        await asyncio.gather(*(_one(server) for server in servers if server.enabled))

    async def poll_one(self, slug: str) -> None:
        """Probe a single server immediately, outside the normal poll cycle — used right after
        registering a server (so it doesn't sit at 'unknown' for up to a full interval) and for
        an explicit re-probe request from the UI."""
        try:
            server = await self._repo.get(slug)
        except ServerNotFoundError:
            return
        if server.enabled:
            await self._probe_and_store(server)

    async def _probe_and_store(self, server: ServerRecord) -> None:
        # Overall per-server deadline: bounds the probe as a whole (each HTTP exchange inside it
        # is also bounded individually), so a server that stalls anywhere — a secret provider call
        # included — becomes "unhealthy, timed out" instead of occupying this slot indefinitely.
        try:
            health_status, protocol, discover_json, health_reason = await asyncio.wait_for(
                probe_server(
                    self._client, self._handshakes, server, secret_provider=self._secrets,
                    token_issuer=self._token_issuer,
                ),
                timeout=PROBE_DEADLINE_SECONDS,
            )
        except asyncio.TimeoutError:
            logger.info("probe for '%s' exceeded its %ss deadline", server.slug, PROBE_DEADLINE_SECONDS)
            health_status, protocol, discover_json = "unhealthy", None, None
            health_reason = f"{PROBE_TIMEOUT_PREFIX}probe exceeded {PROBE_DEADLINE_SECONDS:g}s"
        # A token-mode server that probes healthy WITH its token must also refuse a request
        # WITHOUT one, and a token for another audience. Protocol/discover data from the good probe is kept; only status and reason
        # change. Runs only when the authenticated probe passed (otherwise the server is already
        # unhealthy and a second request would add nothing).
        if health_status == "healthy" and server.credential_mode == "token":
            not_enforced = await check_auth_enforced(server, self._token_issuer)
            if not_enforced is not None:
                health_status, health_reason = "unhealthy", not_enforced
        await self._repo.set_health(
            server.slug, health_status=health_status, upstream_protocol=protocol,
            discover_json=json.dumps(discover_json) if discover_json else None,
            health_reason=health_reason,
        )
        # Item 3 (features_08_05_26): fire only on the EDGE (healthy/unknown -> unhealthy), using
        # the status this same ServerRecord carried going INTO this probe — never on every poll
        # tick while a server stays down, which would turn a single outage into one webhook per
        # interval for as long as it lasts.
        if self._webhooks is not None and server.health_status != "unhealthy" and health_status == "unhealthy":
            await self._webhooks.notify_unhealthy(server.slug)

    async def _loop(self) -> None:
        while True:
            try:
                await self.poll_once()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("health poll iteration failed")
            await asyncio.sleep(self._interval)
