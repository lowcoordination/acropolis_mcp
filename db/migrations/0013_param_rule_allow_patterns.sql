-- Issue #121: allow_patterns on ParamRule — allow-semantics for blast-radius limits.
--
-- The issue text says "no migration — rides the existing JSON policy column," but that
-- premise doesn't hold for param rules: unlike dlp_detectors (which rides the
-- server_policies.dlp_config JSONB column from 0007), param rules live in the NORMALIZED
-- param_rules table where every rule field is its own column — and there is no generic JSON
-- column here to ride. The smallest change consistent with how this table already stores
-- operator regexes is a dedicated JSONB column mirroring block_patterns: same codec (the
-- repo layer json.dumps/json.loads it; asyncpg needs an explicit codec either way — see
-- db/database.py's _init_connection), same NULL-means-empty read handling in db/repo.py.
--
-- Nullable, no default rewrite, no backfill: existing rows keep NULL, which db/repo.py
-- decodes as [] (no allow constraint). Semantics live in db/models.py (compile-on-write
-- validation) and argus/policy.py's _check_param (deny-wins, fail-closed UNDETERMINED).

ALTER TABLE param_rules ADD COLUMN IF NOT EXISTS allow_patterns JSONB;
