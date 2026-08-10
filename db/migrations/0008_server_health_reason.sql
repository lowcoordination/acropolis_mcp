-- Ported from the SQLite series' 0009_server_health_reason.sql (renumbered).
--
-- HealthPoller needs to distinguish "unhealthy because the upstream itself is down/unreachable"
-- from "unhealthy because the configured credential couldn't be resolved" — a secret-resolution
-- failure must read unhealthy with a CLEAR, DISTINGUISHABLE reason, not something indistinguishable
-- from a normal network-level outage. Reusing `discover_json` would conflate it with its existing
-- job (the cached server/discover response body, consumed by argus/discover.py); a dedicated
-- column keeps both meanings clean and independently nullable.

ALTER TABLE servers ADD COLUMN IF NOT EXISTS health_reason TEXT;
