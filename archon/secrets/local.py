"""The `local` SecretProvider — pass-through, byte-identical to pre-feature behaviour.

This is the default provider and the regression guard for the entire enterprise #5 item: every
existing test that exercises `upstream_auth_header` must pass unchanged with `local` selected,
because `local` selected IS the pre-feature codepath. `resolve()` returns whatever string it was
given, unmodified; `store()` returns the value unchanged (so a literal typed into the UI is
stored as a literal, exactly as it always has been); `delete()` is a no-op (there is nothing
external to clean up — the value lives only in the `servers.upstream_auth_header` column, and
clearing that column is ServerRepo.update's job, not this provider's).
"""
from __future__ import annotations


class LocalSecretProvider:
    async def resolve(self, ref: str) -> str:
        return ref

    async def store(self, ref: str, value: str) -> str:
        return value

    async def delete(self, ref: str) -> None:
        return None
