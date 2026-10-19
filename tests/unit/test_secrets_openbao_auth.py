"""How the `openbao` secret provider authenticates to the secret server.

Three ways, all opt-in and all platform-neutral (the client only does HTTP and reads files):

  * a static token (unchanged);
  * AppRole, with the secret_id either inline (unchanged) or read from a FILE, so Docker secrets,
    Kubernetes Secret mounts and systemd credentials can keep it out of the process environment
    (where it is readable through /proc/<pid>/environ and `docker inspect`);
  * Kubernetes auth, where the credential is the pod's own short-lived service-account token read
    from a file, so no static secret exists at all.

The stub below implements just enough of the login endpoints and KV v2 to exercise the CLIENT:
it records every login and issues a distinct token per login, so a test can tell which login a
KV read rode on. Like test_secrets_openbao_stub.py this is a protocol-shape test, not a claim
about real Vault/OpenBao behaviour.
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from archon.secrets import SecretResolutionError
from archon.secrets.openbao import OpenBaoConfigError, OpenBaoSecretProvider

REF = "vault://secret/acropolis/svc#token"


class _Server:
    """Shared, mutable state of one stub server."""

    def __init__(self) -> None:
        self.approle_creds = {"role_id": "role-1", "secret_id": "sid-1"}
        self.k8s_role = "acropolis"
        self.k8s_mount = "kubernetes"
        self.accepted_jwts: set[str] = set()
        self.lease_seconds = 3600
        self.logins: list[tuple[str, dict]] = []  # (path, body)
        self.issued: set[str] = set()
        self.kv: dict[str, dict] = {"secret/data/acropolis/svc": {"token": "the-secret-value"}}
        self.reads_with: list[str] = []  # X-Vault-Token of each KV read, in order
        self.login_delay = 0.0  # seconds the login endpoint takes to answer (a hang)
        self._lock = threading.Lock()

    def new_token(self) -> str:
        with self._lock:
            tok = f"tok-{len(self.issued) + 1}"
            self.issued.add(tok)
            return tok


def _handler(state: _Server):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):  # quiet
            pass

        def _send(self, status: int, body: dict) -> None:
            raw = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length) or b"{}")
            path = self.path.split("/v1/", 1)[1]
            if path.endswith("/login"):
                state.logins.append((path, body))
                if state.login_delay:
                    time.sleep(state.login_delay)
                if path == "auth/approle/login":
                    ok = (body.get("role_id"), body.get("secret_id")) == (
                        state.approle_creds["role_id"], state.approle_creds["secret_id"])
                elif path == f"auth/{state.k8s_mount}/login":
                    ok = body.get("role") == state.k8s_role and body.get("jwt") in state.accepted_jwts
                else:
                    return self._send(404, {"errors": ["no such auth mount"]})
                try:
                    if not ok:
                        return self._send(403, {"errors": ["permission denied"]})
                    return self._send(200, {"auth": {
                        "client_token": state.new_token(), "lease_duration": state.lease_seconds}})
                except (BrokenPipeError, ConnectionResetError):
                    return  # the client gave up (a timeout test); nothing to report
            self._send(404, {"errors": []})

        def do_GET(self):
            token = self.headers.get("X-Vault-Token", "")
            state.reads_with.append(token)
            if token not in state.issued:
                return self._send(403, {"errors": ["permission denied"]})
            data = state.kv.get(self.path.split("/v1/", 1)[1])
            if data is None:
                return self._send(404, {"errors": []})
            self._send(200, {"data": {"data": data, "metadata": {"version": 1}}})

    return Handler


@contextlib.contextmanager
def _stub():
    state = _Server()
    # Threading, with a deep backlog: the concurrency tests open many connections at once, and a
    # single-threaded server with the default backlog of 5 wedges (found when a deliberately
    # broken provider made the test hang instead of fail).
    server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(state))
    server.daemon_threads = True
    server.request_queue_size = 128
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield state, f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join(timeout=5.0)


def _expire_cached_login(provider: OpenBaoSecretProvider) -> None:
    """Force the next resolve to log in again without sleeping through a lease."""
    provider._login_token_expires_at = 0.0


def _write(path: Path, text: str) -> Path:
    path.write_text(text)
    return path


# --------------------------------------------------------------------- Kubernetes auth

@pytest.mark.asyncio
async def test_kubernetes_login_then_resolve(tmp_path):
    jwt = _write(tmp_path / "token", "k8s-jwt-1\n")  # kubelet-written files end in a newline
    with _stub() as (state, url):
        state.accepted_jwts = {"k8s-jwt-1"}
        p = OpenBaoSecretProvider(url, auth_method="kubernetes", k8s_role="acropolis",
                                  k8s_token_file=str(jwt), ttl_seconds=0.0)
        try:
            assert await p.resolve(REF) == "the-secret-value"
            assert await p.resolve(REF) == "the-secret-value"
        finally:
            await p.aclose()
        assert state.logins == [("auth/kubernetes/login", {"role": "acropolis", "jwt": "k8s-jwt-1"})]
        assert state.reads_with == ["tok-1", "tok-1"], "the cached login token must be reused"


@pytest.mark.asyncio
async def test_the_token_file_is_reread_on_every_login(tmp_path):
    """Kubernetes rotates a projected token file in place. A client that read it once at boot
    would send an expired JWT at its first re-login."""
    jwt = _write(tmp_path / "token", "k8s-jwt-1")
    with _stub() as (state, url):
        state.accepted_jwts = {"k8s-jwt-1"}
        p = OpenBaoSecretProvider(url, auth_method="kubernetes", k8s_role="acropolis",
                                  k8s_token_file=str(jwt), ttl_seconds=0.0)
        try:
            await p.resolve(REF)
            state.accepted_jwts = {"k8s-jwt-2"}  # the old token is no longer valid
            jwt.write_text("k8s-jwt-2")
            _expire_cached_login(p)
            assert await p.resolve(REF) == "the-secret-value"
        finally:
            await p.aclose()
        assert [b["jwt"] for _, b in state.logins] == ["k8s-jwt-1", "k8s-jwt-2"]
        assert state.reads_with == ["tok-1", "tok-2"]


@pytest.mark.asyncio
async def test_custom_auth_mount(tmp_path):
    jwt = _write(tmp_path / "token", "k8s-jwt-1")
    with _stub() as (state, url):
        state.accepted_jwts, state.k8s_mount = {"k8s-jwt-1"}, "k8s-prod"
        p = OpenBaoSecretProvider(url, auth_method="kubernetes", k8s_role="acropolis",
                                  k8s_token_file=str(jwt), k8s_mount="k8s-prod", ttl_seconds=0.0)
        try:
            assert await p.resolve(REF) == "the-secret-value"
        finally:
            await p.aclose()
        assert state.logins[0][0] == "auth/k8s-prod/login"


@pytest.mark.asyncio
async def test_rejected_kubernetes_login_is_an_explicit_error_that_never_echoes_the_jwt(tmp_path):
    jwt = _write(tmp_path / "token", "SUPER-SECRET-JWT-VALUE")
    with _stub() as (state, url):
        state.accepted_jwts = set()  # the server rejects it
        p = OpenBaoSecretProvider(url, auth_method="kubernetes", k8s_role="acropolis",
                                  k8s_token_file=str(jwt), ttl_seconds=0.0)
        try:
            with pytest.raises(SecretResolutionError) as exc:
                await p.resolve(REF)
        finally:
            await p.aclose()
        text = f"{exc.value} {exc.value!r} {exc.value.reason} {exc.value.ref}"
        assert "Kubernetes" in text and "403" in text
        assert "SUPER-SECRET-JWT-VALUE" not in text


@pytest.mark.asyncio
@pytest.mark.parametrize("make_file,expect", [
    (lambda d: d / "does-not-exist", "could not read"),
    (lambda d: _write(d / "empty", "  \n"), "empty"),
    (lambda d: _write(d / "huge", "A" * 70_000), "too large"),
])
async def test_unusable_token_file_is_an_explicit_error(tmp_path, make_file, expect):
    with _stub() as (state, url):
        p = OpenBaoSecretProvider(url, auth_method="kubernetes", k8s_role="acropolis",
                                  k8s_token_file=str(make_file(tmp_path)), ttl_seconds=0.0)
        try:
            with pytest.raises(SecretResolutionError) as exc:
                await p.resolve(REF)
        finally:
            await p.aclose()
        assert expect in exc.value.reason.lower()
        assert "A" * 100 not in exc.value.reason, "file contents must never appear in an error"
        assert state.logins == [], "no login may be attempted without a credential"


@pytest.mark.asyncio
async def test_a_short_read_does_not_silently_truncate_the_credential(tmp_path, monkeypatch):
    """os.read may legally return fewer bytes than the file holds (network filesystems, signals). A
    credential cut short is worse than an error: it would be sent as if it were the whole thing."""
    value = "k8s-jwt-" + "x" * 200
    jwt = _write(tmp_path / "token", value)
    import archon.secrets.openbao as mod

    real = mod._read
    monkeypatch.setattr(mod, "_read", lambda fd, n: real(fd, min(n, 7)))  # 7 bytes at a time
    with _stub() as (state, url):
        state.accepted_jwts = {value}
        p = OpenBaoSecretProvider(url, auth_method="kubernetes", k8s_role="acropolis",
                                  k8s_token_file=str(jwt), ttl_seconds=0.0)
        try:
            assert await p.resolve(REF) == "the-secret-value"
        finally:
            await p.aclose()
        assert state.logins[0][1]["jwt"] == value


# --------------------------------------------------------------------- AppRole, inline and file

@pytest.mark.asyncio
async def test_approle_inline_secret_id_still_works():
    """Backward compatibility: the existing configuration is untouched."""
    with _stub() as (state, url):
        p = OpenBaoSecretProvider(url, role_id="role-1", secret_id="sid-1", ttl_seconds=0.0)
        try:
            assert await p.resolve(REF) == "the-secret-value"
        finally:
            await p.aclose()
        assert state.logins == [("auth/approle/login", {"role_id": "role-1", "secret_id": "sid-1"})]


@pytest.mark.asyncio
async def test_approle_secret_id_from_file_is_stripped_and_reread(tmp_path):
    f = _write(tmp_path / "secret_id", "sid-1\n")
    with _stub() as (state, url):
        p = OpenBaoSecretProvider(url, role_id="role-1", secret_id_file=str(f), ttl_seconds=0.0)
        try:
            assert await p.resolve(REF) == "the-secret-value"
            state.approle_creds["secret_id"] = "sid-2"  # the operator rotates the credential...
            f.write_text("sid-2\n")                      # ...and the mounted file
            _expire_cached_login(p)
            assert await p.resolve(REF) == "the-secret-value"
        finally:
            await p.aclose()
        assert [b["secret_id"] for _, b in state.logins] == ["sid-1", "sid-2"]


@pytest.mark.asyncio
async def test_missing_secret_id_file_is_an_explicit_error(tmp_path):
    with _stub() as (state, url):
        p = OpenBaoSecretProvider(url, role_id="role-1", secret_id_file=str(tmp_path / "nope"), ttl_seconds=0.0)
        try:
            with pytest.raises(SecretResolutionError) as exc:
                await p.resolve(REF)
        finally:
            await p.aclose()
        assert "could not read" in exc.value.reason.lower()
        assert state.logins == []


# --------------------------------------------------------------------- concurrency

@pytest.mark.asyncio
async def test_concurrent_cold_resolves_log_in_once(tmp_path):
    """When the login token expires, every in-flight request would otherwise log in separately: with
    Kubernetes auth each login is a TokenReview call against the API server."""
    jwt = _write(tmp_path / "token", "k8s-jwt-1")
    with _stub() as (state, url):
        state.accepted_jwts = {"k8s-jwt-1"}
        p = OpenBaoSecretProvider(url, auth_method="kubernetes", k8s_role="acropolis",
                                  k8s_token_file=str(jwt), ttl_seconds=0.0)
        try:
            results = await asyncio.gather(*[p.resolve(REF) for _ in range(16)])
        finally:
            await p.aclose()
        assert results == ["the-secret-value"] * 16
        assert len(state.logins) == 1, f"{len(state.logins)} logins for 16 concurrent resolves"


@pytest.mark.asyncio
async def test_failing_logins_do_not_queue_one_behind_another(tmp_path):
    """The login is single-flight behind a lock. If every waiter then retried its own login in turn
    after a failure, 8 requests against a hung login endpoint would take 8 x the request timeout and
    hammer the endpoint (with Kubernetes auth, the API server). A failure is remembered briefly so the
    waiters fail fast with the same error."""
    jwt = _write(tmp_path / "token", "k8s-jwt-1")
    with _stub() as (state, url):
        state.accepted_jwts = {"k8s-jwt-1"}
        state.login_delay = 1.2  # the login endpoint hangs past the 0.3 s request timeout
        p = OpenBaoSecretProvider(url, auth_method="kubernetes", k8s_role="acropolis",
                                  k8s_token_file=str(jwt), ttl_seconds=0.0, request_timeout_seconds=0.3)
        try:
            start = time.monotonic()
            results = await asyncio.gather(*[p.resolve(REF) for _ in range(8)], return_exceptions=True)
            elapsed = time.monotonic() - start
        finally:
            await p.aclose()
        assert all(isinstance(r, SecretResolutionError) for r in results), results
        assert elapsed < 1.0, f"8 concurrent failing logins took {elapsed:.1f}s: they queued behind each other"
        assert len(state.logins) == 1, f"{len(state.logins)} login attempts for 8 concurrent resolves"


@pytest.mark.asyncio
async def test_a_failed_login_is_retried_after_the_backoff(tmp_path):
    jwt = _write(tmp_path / "token", "k8s-jwt-1")
    with _stub() as (state, url):
        state.accepted_jwts = set()  # rejected at first
        p = OpenBaoSecretProvider(url, auth_method="kubernetes", k8s_role="acropolis",
                                  k8s_token_file=str(jwt), ttl_seconds=0.0)
        try:
            with pytest.raises(SecretResolutionError):
                await p.resolve(REF)
            state.accepted_jwts = {"k8s-jwt-1"}  # the operator fixes it
            with pytest.raises(SecretResolutionError):  # still inside the backoff: no new attempt
                await p.resolve(REF)
            assert len(state.logins) == 1
            p._login_failed_until = 0.0  # backoff over
            assert await p.resolve(REF) == "the-secret-value"
            assert len(state.logins) == 2
        finally:
            await p.aclose()


@pytest.mark.asyncio
async def test_a_credential_path_that_is_not_a_regular_file_is_refused_not_blocked_on(tmp_path):
    """A FIFO with no writer blocks a read forever, and the read happens while the login lock is
    held, which would freeze every secret resolution. Only regular files are read."""
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)
    with _stub() as (state, url):
        p = OpenBaoSecretProvider(url, auth_method="kubernetes", k8s_role="acropolis",
                                  k8s_token_file=str(fifo), ttl_seconds=0.0)
        try:
            with pytest.raises(SecretResolutionError) as exc:
                await asyncio.wait_for(p.resolve(REF), timeout=3.0)
        finally:
            # If a regression left a thread stuck opening the FIFO, release it so the test FAILS
            # (TimeoutError above) instead of hanging the whole run at event-loop shutdown.
            try:
                os.close(os.open(fifo, os.O_WRONLY | os.O_NONBLOCK))
            except OSError:
                pass
            await p.aclose()
        assert "regular file" in exc.value.reason
        assert state.logins == []


# --------------------------------------------------------------------- configuration

@pytest.mark.parametrize("kwargs", [
    {"token": "t", "auth_method": "bogus"},                                       # unknown method
    {"auth_method": "kubernetes"},                                                # no role
    {"auth_method": "kubernetes", "k8s_role": ""},                                # empty role
    {"auth_method": "kubernetes", "k8s_role": "r", "token": "t"},                 # conflicting credentials
    {"auth_method": "kubernetes", "k8s_role": "r", "role_id": "x", "secret_id": "y"},
    {"auth_method": "approle", "token": "t"},                                     # approle without its parts
    {"auth_method": "approle", "role_id": "x"},
    {"auth_method": "token"},
    {"role_id": "x", "secret_id": "y", "secret_id_file": "/some/file"},           # both ways to give the secret_id
    {"role_id": "x"},                                                             # half an AppRole
    {"secret_id_file": "/some/file"},
    {"k8s_role": "r"},                                                            # role without selecting the method
    {},                                                                           # nothing at all
])
def test_invalid_configuration_fails_at_construction(kwargs):
    with pytest.raises(OpenBaoConfigError):
        OpenBaoSecretProvider("http://127.0.0.1:8200", **kwargs)


@pytest.mark.parametrize("mount", ["", "..", "../sys", "a/../b", "a//b", "/abs", "trail/", "a b", "a?b", "a#b",
                                   "%2e%2e", "a\nb", "k8s;x", "kubernetes\n", "kubernetes\r\n"])
def test_the_auth_mount_cannot_escape_the_auth_namespace(mount):
    """The mount name is interpolated into the login URL."""
    with pytest.raises(OpenBaoConfigError):
        OpenBaoSecretProvider("http://127.0.0.1:8200", auth_method="kubernetes", k8s_role="r", k8s_mount=mount)


@pytest.mark.parametrize("mount", ["kubernetes", "k8s-prod", "team_a.k8s", "k8s/prod"])
def test_ordinary_mount_names_are_accepted(mount):
    OpenBaoSecretProvider("http://127.0.0.1:8200", auth_method="kubernetes", k8s_role="r", k8s_mount=mount)


@pytest.mark.parametrize("kwargs", [
    {"token": "t"},
    {"auth_method": "token", "token": "t"},
    {"role_id": "x", "secret_id": "y"},
    {"auth_method": "approle", "role_id": "x", "secret_id": "y"},
    {"role_id": "x", "secret_id_file": "/some/file"},
    {"auth_method": "kubernetes", "k8s_role": "r"},
    # Backward compatibility: with no method selected, a token alongside AppRole credentials has
    # always meant "use the token". That must not become a startup error.
    {"token": "t", "role_id": "x", "secret_id": "y"},
])
def test_valid_configurations_are_accepted(kwargs):
    OpenBaoSecretProvider("http://127.0.0.1:8200", **kwargs)


# --------------------------------------------------------------------- settings wiring

@pytest.mark.asyncio
async def test_token_still_wins_over_approle_when_no_method_is_selected():
    with _stub() as (state, url):
        p = OpenBaoSecretProvider(url, token="static-tok", role_id="role-1", secret_id="sid-1")
        try:
            assert p._auth_method == "token"
            assert await p._current_token() == "static-tok"
        finally:
            await p.aclose()
        assert state.logins == []


def test_build_secret_provider_passes_the_new_settings_through(tmp_path, monkeypatch):
    from archon.secrets import build_secret_provider
    from archon.settings import Settings

    f = _write(tmp_path / "jwt", "x")
    monkeypatch.setenv("ACROPOLIS_VAULT_ADDR", "http://127.0.0.1:8200")
    monkeypatch.setenv("ACROPOLIS_VAULT_AUTH_METHOD", "kubernetes")
    monkeypatch.setenv("ACROPOLIS_VAULT_K8S_ROLE", "acropolis")
    monkeypatch.setenv("ACROPOLIS_VAULT_K8S_TOKEN_FILE", str(f))
    monkeypatch.setenv("ACROPOLIS_VAULT_K8S_MOUNT", "k8s-prod")
    provider = build_secret_provider(Settings(secret_provider="openbao"))
    assert provider._auth_method == "kubernetes"
    assert provider._k8s_role == "acropolis"
    assert provider._k8s_token_file == str(f)
    assert provider._k8s_mount == "k8s-prod"


def test_settings_defaults_leave_existing_deployments_unchanged():
    from archon.settings import Settings

    s = Settings()
    assert s.vault_auth_method is None
    assert s.vault_secret_id_file is None
    assert s.vault_k8s_role is None
    assert s.vault_k8s_mount == "kubernetes"
    assert s.vault_k8s_token_file == "/var/run/secrets/kubernetes.io/serviceaccount/token"
