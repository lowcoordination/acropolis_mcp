"""Re-encryption of stored `encrypted`-tier credentials (R2, issue #29).

The operator-facing half of secret-key rotation: after deploying a NEW active key at the front
of the key ring (see archon/secrets/encrypted.py's KeyRing), this walks every server's stored
`upstream_auth_header`, decrypts each `enc:v1:` reference through the ring, and re-encrypts it
under the ACTIVE key — making rotation completable ("deploy new active → re-encrypt → drop old
key") rather than permanent dual-key operation.

Deliberately lives in `argus/` (the app layer), not in `archon/secrets/`: the walk needs
ServerRepo, and the secrets package's layering boundary is that it never imports the db layer.

Failure discipline (matches the codebase's never-half-apply norm): a credential that fails to
decrypt (its key is no longer in the ring, or its ciphertext is corrupted) is reported, NOT
touched, and the walk continues — the old ciphertext stays in place, so nothing is ever lost,
and the report names exactly which servers are bricked. The CLI exits non-zero if any failed.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from archon.secrets import SecretResolutionError
from archon.secrets.encrypted import PREFIX


@dataclass
class ReencryptResult:
    scanned: int = 0  # servers examined
    reencrypted: int = 0  # enc:v1: credentials rewritten under the active key
    skipped: int = 0  # servers with no enc:v1: ref (literal / vault:// / none)
    failed: list[tuple[str, str]] = field(default_factory=list)  # (slug, reason)


async def reencrypt_credentials(
    provider, server_repo, *, dry_run: bool = False
) -> ReencryptResult:
    """Walk every server's `upstream_auth_header`; decrypt `enc:v1:` references via the
    provider's ring and re-encrypt them under the provider's ACTIVE key.

    - Literal credentials and `vault://` references are skipped (they are not this provider's
      format — re-encrypting them would either corrupt them (literal) or be meaningless
      (vault handles its own rotation)).
    - A resolve failure is reported and the row is left untouched (see module docstring).
    - `dry_run=True` decrypts and reports but writes nothing — preview is the default, writing
      is the explicit opt-in, same discipline as config import.
    """
    result = ReencryptResult()
    for server in await server_repo.list():
        result.scanned += 1
        ref = server.upstream_auth_header
        if not ref or not ref.startswith(PREFIX):
            result.skipped += 1
            continue
        try:
            plaintext = await provider.resolve(ref)
        except SecretResolutionError as e:
            result.failed.append((server.slug, str(e)))
            continue
        new_ref = await provider.store(f"reencrypt:{server.slug}", plaintext)
        if not dry_run:
            await server_repo.update(server.slug, upstream_auth_header=new_ref)
        result.reencrypted += 1
    return result
