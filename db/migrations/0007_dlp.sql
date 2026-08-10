-- Ported from the SQLite series' 0008_gateway_dlp_config.sql AND 0008_audit_dlp.sql, MERGED.
--
-- These were two separate files with the SAME version number (0008) — which only worked because
-- they targeted two different SQLite files with two independent schema_migrations tables. In one
-- database with one version sequence that collision is not expressible, so the two are merged
-- into a single migration. They were always one logical change (enterprise #10, DLP redaction)
-- split only by which file each ALTER had to land in; merging restores the shape the feature
-- actually had.
--
-- server_policies.dlp_config holds dlp_detectors + dlp_custom_patterns as one JSON value, rather
-- than being further normalized into per-detector rows the way param_rules does for its
-- (server, tool, param) triples — DLP config has no natural per-row key, and the whole point of
-- the feature is a short, operator-edited list per server, not something queried/joined against.
-- JSONB rather than the SQLite original's TEXT: same data, but now actually validated as JSON on
-- write instead of being an opaque string that _decode_dlp_config had to defend against with a
-- try/except JSONDecodeError. That defensive branch stays in the repo anyway (a NULL or a
-- hand-edited row is still possible) but can no longer be reached by this app's own writes.
ALTER TABLE server_policies ADD COLUMN IF NOT EXISTS dlp_config JSONB;

-- Decision-adjacent audit fields recording WHICH detector fired and WHAT action was taken.
-- Deliberately does NOT add a column for the matched/redacted value itself — that must never
-- appear in the audit log (see argus/dlp.py and docs/dlp.md's audit-safety invariant).
-- dlp_action mirrors decision (a BLOCKED row can also carry dlp_action='block'; an ALLOWED row
-- can carry dlp_action='redact' when a call succeeded with a span removed) since a DLP-driven
-- block/redact is otherwise indistinguishable in the `rule` column from any other policy rule.
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS dlp_detector TEXT;
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS dlp_action TEXT;
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS dlp_match_count INTEGER;
