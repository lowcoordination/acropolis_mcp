-- Enterprise #5 (secret backends): HealthPoller needs to distinguish "unhealthy because the
-- upstream itself is down/unreachable" from "unhealthy because the configured credential
-- couldn't be resolved" — the plan is explicit that a secret-resolution failure must read
-- unhealthy with a CLEAR, DISTINGUISHABLE reason, not a generic/opaque failure indistinguishable
-- from a normal network-level outage. Reusing `discover_json` for this would conflate it with
-- its existing job (the cached server/discover response body, consumed by argus/discover.py) —
-- a dedicated column keeps both meanings clean and independently nullable.
--
-- Deliberately NOT part of `upstream_auth_header`'s original migration (0003) — that column
-- predates this feature and this is additive, not a rework of it.

ALTER TABLE servers ADD COLUMN health_reason TEXT;
