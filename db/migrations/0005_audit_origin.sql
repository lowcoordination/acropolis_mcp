-- New feature Item 1 (in-UI tool tester): a "Try it" call must run through the real pipeline
-- (policy, rate limiting, audit) to be trustworthy, but must not pollute the dashboard's
-- blocked/allowed counters or look like a real client's traffic in the audit log. `origin`
-- distinguishes: NULL (normal traffic, the default) vs 'test' (admin-originated Try-it calls).
-- AuditRepo.count_since (which backs /stats) filters to `origin IS NULL` so test traffic never
-- moves the dashboard counters; AuditRepo.query gains an `origin` filter so the Audit page can
-- show or hide test rows explicitly.

ALTER TABLE audit_events ADD COLUMN origin TEXT;
