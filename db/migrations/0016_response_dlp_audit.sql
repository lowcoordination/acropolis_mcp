-- Issue #165 (response DLP): which response detectors fired on a tools/call, how many matches,
-- and whether the response was cut (scan budget, hard read ceiling, or unparseable body).
--
-- Same discipline as 0007's DLP columns: names and counts only. There is no column for a
-- matched or redacted value, and there must never be one (docs/dlp.md, audit-safety invariant).
--
-- All three are NULL when response DLP is off for the server, so every row written before this
-- migration, and every row for a server that never opts in, reads exactly as it did.
-- response_dlp_detectors_fired is the sorted detector names, comma-joined; '' means the
-- response was scanned and nothing fired.
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS response_dlp_detectors_fired TEXT;
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS response_dlp_match_count INTEGER;
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS response_truncated BOOLEAN;
