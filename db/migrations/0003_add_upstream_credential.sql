-- F23 fix (review 2026-08-04, design gap): the servers table had no auth column at all. Net
-- effect before this: passthrough forwarded the CLIENT's own Authorization header to the
-- upstream (that was F5 — a leak, fixed in Plan 1 by stripping it), and bridged built a fresh
-- header dict with no Authorization at all. Once F5 stopped leaking the client's header, any
-- upstream that genuinely needed its own credentials broke outright instead of "working" by
-- accident — this migration is what closes that gap for real.
--
-- Storage decision: plaintext in gateway.db, injected as a literal Authorization header value
-- on outbound upstream requests. NOT encrypted-at-rest, NOT delegated to an external secret
-- store. This matches the security posture already used everywhere else in this schema —
-- session_secret and admin_password_hash (itself a KDF output, not a raw secret, but the
-- comparison point is that this app has no KMS/encryption-key story anywhere) are already
-- plaintext DB rows. Introducing envelope encryption for exactly one column, with the key
-- inevitably ending up in another DB row or an env var right next to it, would add real
-- complexity without changing the actual threat model: anyone who can read gateway.db can
-- already forge an admin session (see the F1 exploit chain) or read every API key's usage
-- metadata. The operator-facing mitigation is the existing one — protect the data volume.

ALTER TABLE servers ADD COLUMN upstream_auth_header TEXT;
