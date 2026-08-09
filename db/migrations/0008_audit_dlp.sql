-- Enterprise #10 (DLP): decision-adjacent audit fields recording WHICH detector fired and
-- WHAT action was taken. Deliberately does NOT add a column for the matched/redacted value
-- itself — that must never appear in the audit log (see argus/dlp.py and docs/dlp.md's
-- audit-safety invariant). dlp_action mirrors decision (BLOCKED rows can also carry
-- dlp_action='block'; ALLOWED rows can carry dlp_action='redact' when a call succeeded with a
-- span removed) since a DLP-driven block/redact is otherwise indistinguishable in the existing
-- `rule` column from any other policy rule.

ALTER TABLE audit_events ADD COLUMN dlp_detector TEXT;
ALTER TABLE audit_events ADD COLUMN dlp_action TEXT;
ALTER TABLE audit_events ADD COLUMN dlp_match_count INTEGER;
