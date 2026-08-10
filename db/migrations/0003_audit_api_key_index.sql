-- Ported from the SQLite series' 0004_audit_api_key_index.sql (renumbered).
--
-- AuditRepo.query's api_key_id filter (paired with ts, since callers filtering by key also want
-- a date range) so "what did this key do" doesn't require a full table scan. The other filters
-- (after/before/search) ride the indexes created in 0001 — api_key_id had none.

CREATE INDEX IF NOT EXISTS idx_audit_api_key ON audit_events(api_key_id, ts);
