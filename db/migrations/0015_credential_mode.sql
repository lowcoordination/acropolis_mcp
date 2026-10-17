-- Issue #134 (upstream token auth): the MECHANISM by which Acropolis authenticates to an
-- upstream server. Three modes:
--   'none'   — no credential injected (the pre-#134 behaviour for any server without an
--              upstream_auth_header; also the explicit "trusted network" choice)
--   'static' — the existing literal/reference upstream_auth_header, injected verbatim
--   'token'  — Acropolis mints a short-lived audience-bound JWT (argus/tokens.py, injected in
--              argus/pipeline.py) and sends it as the Authorization header
--
-- The column SELECTS the mechanism; upstream_auth_header stays as the storage for 'static' and
-- is ignored under 'token'. DEFAULT 'none' backfills every existing row to "no token", so NO
-- server's behaviour changes until an operator flips the mode (spec §2). The CHECK mirrors the
-- existing servers_health_status / server_policies_mode constraints: enum-at-rest so an invalid
-- value can never be written by hand, with application-layer validation layered on top at the
-- API (archon/schemas.py) and on config import (archon/config_io.py).
--
-- Deliberately TEXT + CHECK, not a Postgres ENUM type: same reasoning as health_status and
-- server_policies.mode — adding a mode later is a CHECK migration, not a TYPE swap.
ALTER TABLE servers ADD COLUMN IF NOT EXISTS credential_mode TEXT NOT NULL DEFAULT 'none';
ALTER TABLE servers ADD CONSTRAINT servers_credential_mode
    CHECK (credential_mode IN ('none', 'static', 'token'));
