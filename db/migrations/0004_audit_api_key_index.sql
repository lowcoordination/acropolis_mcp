-- Enhancement Item B (roadmap #5): AuditRepo.query gains an api_key_id filter (paired with
-- ts, since callers filtering by key also want a date range) so "what did this key do" doesn't
-- require a full table scan. The other new filters (after/before/search) ride existing indexes
-- (idx_audit_ts, idx_audit_server_ts, idx_audit_decision) — api_key_id had none.

CREATE INDEX IF NOT EXISTS idx_audit_api_key ON audit_events(api_key_id, ts);
