"""Trusting a private CA for the secret server (`ACROPOLIS_VAULT_CA_FILE`).

An in-cluster OpenBao is often served over TLS from an internal CA that no public trust store
knows. Without this setting the only ways to reach it are plain http or replacing the whole
process trust bundle (`SSL_CERT_FILE`), which would also drop the public CAs for every other
HTTPS call the process makes. `ca_file` trusts exactly the CA(s) in one PEM file for this client
and nothing else.

These tests run a REAL TLS server with a throwaway CA generated in the test, so the verification
that is being claimed is the verification that ran.
"""
from __future__ import annotations

import contextlib
import datetime
import ipaddress
import json
import logging
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from archon.secrets import SecretResolutionError
from archon.secrets.openbao import OpenBaoConfigError, OpenBaoSecretProvider

REF = "vault://secret/acropolis/svc#token"


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def _make_ca(cn: str):
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(cn)).issuer_name(_name(cn)).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.KeyUsage(
            digital_signature=False, content_commitment=False, key_encipherment=False, data_encipherment=False,
            key_agreement=False, key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False),
            critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _make_leaf(ca_key, ca_cert, san_ip: str = "127.0.0.1"):
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name("stub")).issuer_name(ca_cert.subject).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        # Python's default TLS context (VERIFY_X509_STRICT since 3.13) rejects a leaf with no
        # Authority Key Identifier, so a CA that omits it produces certificates this client refuses.
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(san_ip))]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    return key, cert


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    d = tmp_path_factory.mktemp("pki")
    ca_key, ca_cert = _make_ca("Test Internal CA")
    other_key, other_cert = _make_ca("Some Other CA")
    leaf_key, leaf_cert = _make_leaf(ca_key, ca_cert)
    wrong_name_key, wrong_name_cert = _make_leaf(ca_key, ca_cert, san_ip="192.0.2.1")
    paths = {}
    for name, cert in (("ca", ca_cert), ("other", other_cert), ("leaf", leaf_cert), ("wrong", wrong_name_cert)):
        paths[name] = d / f"{name}.pem"
        paths[name].write_bytes(_pem(cert))
    for name, key in (("leaf", leaf_key), ("wrong", wrong_name_key)):
        paths[f"{name}_key"] = d / f"{name}.key"
        paths[f"{name}_key"].write_bytes(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return paths


@contextlib.contextmanager
def _tls_stub(cert: Path, key: Path):
    """A KV v2 stub behind TLS that accepts a static token and serves one secret."""
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            if self.headers.get("X-Vault-Token") != "static-tok":
                body, status = {"errors": ["permission denied"]}, 403
            else:
                body, status = {"data": {"data": {"token": "the-secret-value"}, "metadata": {"version": 1}}}, 200
            raw = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"https://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join(timeout=5.0)


@pytest.mark.asyncio
async def test_a_server_signed_by_the_configured_ca_is_trusted(pki):
    with _tls_stub(pki["leaf"], pki["leaf_key"]) as url:
        p = OpenBaoSecretProvider(url, token="static-tok", ca_file=str(pki["ca"]))
        try:
            assert await p.resolve(REF) == "the-secret-value"
        finally:
            await p.aclose()


@pytest.mark.asyncio
async def test_without_the_setting_a_private_ca_is_not_trusted(pki):
    """The control: the same server, no ca_file. If this passed, the test above proved nothing."""
    with _tls_stub(pki["leaf"], pki["leaf_key"]) as url:
        p = OpenBaoSecretProvider(url, token="static-tok")
        try:
            with pytest.raises(SecretResolutionError):
                await p.resolve(REF)
        finally:
            await p.aclose()


@pytest.mark.asyncio
async def test_a_different_ca_in_the_file_does_not_trust_the_server(pki):
    with _tls_stub(pki["leaf"], pki["leaf_key"]) as url:
        p = OpenBaoSecretProvider(url, token="static-tok", ca_file=str(pki["other"]))
        try:
            with pytest.raises(SecretResolutionError):
                await p.resolve(REF)
        finally:
            await p.aclose()


@pytest.mark.asyncio
async def test_the_server_name_is_still_checked_against_the_certificate(pki):
    """Trusting a CA must not turn off hostname verification: this leaf is validly signed by the
    trusted CA but is for a different address than the one connected to."""
    with _tls_stub(pki["wrong"], pki["wrong_key"]) as url:
        p = OpenBaoSecretProvider(url, token="static-tok", ca_file=str(pki["ca"]))
        try:
            with pytest.raises(SecretResolutionError):
                await p.resolve(REF)
        finally:
            await p.aclose()


def test_the_context_trusts_only_the_file_and_keeps_verification_on(pki):
    """A context that ALSO loaded the system bundle would trust every public CA for this client.
    There is no public-CA server to connect to offline, so assert on the context itself."""
    from archon.secrets.openbao import _ssl_context_from_ca_file

    ctx = _ssl_context_from_ca_file(str(pki["ca"]))
    subjects = [dict(rdn[0] for rdn in c["subject"]) for c in ctx.get_ca_certs()]
    assert subjects == [{"commonName": "Test Internal CA"}]
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is True


def test_the_system_trust_bundle_is_never_loaded(pki, monkeypatch):
    """The system bundle may be a hashed directory that `get_ca_certs()` does not list, so the
    subject check above cannot see it; assert the call that would load it is never made."""
    from archon.secrets.openbao import _ssl_context_from_ca_file

    def boom(self, *a, **k):
        raise AssertionError("load_default_certs called: the public CAs would be trusted too")

    monkeypatch.setattr(ssl.SSLContext, "load_default_certs", boom)
    _ssl_context_from_ca_file(str(pki["ca"]))


@pytest.mark.parametrize("content", [None, "", "not a certificate\n"], ids=["missing", "empty", "junk"])
def test_an_unusable_ca_file_fails_at_construction(tmp_path, content):
    path = tmp_path / "ca.pem"
    if content is not None:
        path.write_text(content)
    with pytest.raises(OpenBaoConfigError) as e:
        OpenBaoSecretProvider("https://127.0.0.1:8200", token="t", ca_file=str(path))
    assert "ca_file" in str(e.value)


def test_a_directory_is_not_a_ca_file(tmp_path):
    with pytest.raises(OpenBaoConfigError):
        OpenBaoSecretProvider("https://127.0.0.1:8200", token="t", ca_file=str(tmp_path))


def test_a_ca_file_with_a_plain_http_address_is_refused(pki):
    """A CA file next to an http:// address would look like transport security and give none.
    The file is valid, so it is the scheme being refused and not an unreadable path."""
    with pytest.raises(OpenBaoConfigError) as e:
        OpenBaoSecretProvider("http://127.0.0.1:8200", token="t", ca_file=str(pki["ca"]))
    assert "https" in str(e.value)


def test_a_ca_file_and_an_injected_client_are_refused(pki):
    import httpx
    with pytest.raises(OpenBaoConfigError) as e:
        OpenBaoSecretProvider("https://127.0.0.1:8200", token="t", ca_file=str(pki["ca"]), client=httpx.AsyncClient())
    assert "injected client" in str(e.value)


def test_an_empty_ca_file_setting_means_unset(pki):
    """`ACROPOLIS_VAULT_CA_FILE=""` (an env var present but blank) must behave as unset, not as
    the path ''."""
    OpenBaoSecretProvider("https://127.0.0.1:8200", token="t", ca_file="")


def test_the_ca_file_error_never_prints_the_files_contents(tmp_path, caplog):
    junk = tmp_path / "junk.pem"
    junk.write_text("-----BEGIN PRIVATE KEY-----\nTOP-SECRET-BYTES\n-----END PRIVATE KEY-----\n")
    with pytest.raises(OpenBaoConfigError) as e:
        OpenBaoSecretProvider("https://127.0.0.1:8200", token="t", ca_file=str(junk))
    assert "TOP-SECRET-BYTES" not in str(e.value)
    assert "TOP-SECRET-BYTES" not in caplog.text


def test_https_with_a_ca_file_does_not_log_the_plain_http_warning(pki, caplog):
    with caplog.at_level(logging.WARNING):
        OpenBaoSecretProvider("https://openbao.vault-system.svc:8443", token="t", ca_file=str(pki["ca"]))
    assert "plain http" not in caplog.text


def test_build_secret_provider_passes_the_ca_file_through(pki, monkeypatch):
    from archon.secrets import build_secret_provider
    from archon.settings import Settings

    monkeypatch.setenv("ACROPOLIS_VAULT_ADDR", "https://127.0.0.1:8443")
    monkeypatch.setenv("ACROPOLIS_VAULT_TOKEN", "t")
    monkeypatch.setenv("ACROPOLIS_VAULT_CA_FILE", str(pki["ca"]))
    provider = build_secret_provider(Settings(secret_provider="openbao"))
    assert provider._ca_file == str(pki["ca"])


def test_the_setting_defaults_to_unset():
    from archon.settings import Settings

    assert Settings().vault_ca_file is None
