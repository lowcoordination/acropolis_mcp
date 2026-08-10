-- Ported from the SQLite series' 0005_audit_origin.sql (renumbered).
--
-- In-UI tool tester ("Try it"): a test call must run through the real pipeline (policy, rate
-- limiting, audit) to be trustworthy, but must not pollute the dashboard's blocked/allowed
-- counters or look like a real client's traffic. `origin` distinguishes: NULL (normal traffic,
-- the default) vs 'test' (admin-originated Try-it calls). AuditRepo.count_since (which backs
-- /stats) filters to `origin IS NULL`; AuditRepo.query gains an `origin` filter so the Audit
-- page can show or hide test rows explicitly.

ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS origin TEXT;
