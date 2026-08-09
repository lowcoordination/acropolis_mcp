-- 0008_dlp_config.sql: DLP detector config (enterprise #10).
--
-- CORRECTION to the original plan doc (10-dlp-redaction.md), documented here and in the PR
-- description rather than silently reconciled: the plan assumed ServerPolicy is "stored as
-- JSON... rides the existing column, no migration needed." That premise does not hold for this
-- codebase as it actually exists — server_policies/tool_policies/param_rules are normalized
-- SQL tables (see ServerRepo.set_policy/get_policy in db/repo.py), not a JSON blob. There IS no
-- existing JSON column to ride.
--
-- Given that, dlp_detectors + dlp_custom_patterns are stored as a single JSON TEXT column on
-- server_policies, rather than further normalizing into per-detector rows the way param_rules
-- does for its (server, tool, param) triples — DLP config has no natural per-row key the way a
-- param rule has (tool_name, param_name), and the whole point of this feature is a short,
-- operator-edited list per server, not something queried/joined against elsewhere. A single
-- JSON column here mirrors how tool_policies.rate_limit and api_keys.server_scopes already
-- hold small structured values as TEXT in this same schema, so it's consistent with existing
-- precedent even though it isn't the *literal* "no migration" claim from the plan doc.

ALTER TABLE server_policies ADD COLUMN dlp_config TEXT;
