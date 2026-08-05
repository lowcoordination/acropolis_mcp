-- F4 fix (review 2026-08-04): 0001's CHECK (slug GLOB '[a-z0-9-]*') only constrains the FIRST
-- character — GLOB '*' matches any sequence of ANY characters after that, so 'a_b', 'ab__cd',
-- 'a/../b', and 'a b' all passed it. The application-layer fix (archon/schemas.py's
-- _validate_slug) closes the create path; this tightens the DB-level constraint itself as
-- defense in depth, so a row can never violate it regardless of how it was inserted.
--
-- SQLite has no ALTER TABLE ... ADD/MODIFY CONSTRAINT — tightening a CHECK requires the
-- standard rebuild-in-place pattern: new table, copy rows, drop old, rename. Never edit 0001
-- in place (it's already shipped) — this is a genuinely new forward migration.

PRAGMA foreign_keys=OFF;

CREATE TABLE servers_new (
    id INTEGER PRIMARY KEY,
    slug TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    upstream_url TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    in_aggregate INTEGER NOT NULL DEFAULT 1,
    upstream_protocol TEXT,
    health_status TEXT NOT NULL DEFAULT 'unknown',
    last_seen_at TEXT,
    discover_json TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK (slug GLOB '[a-z0-9-]*' AND NOT slug GLOB '*[^a-z0-9-]*'),
    CHECK (health_status IN ('unknown', 'healthy', 'unhealthy'))
);

INSERT INTO servers_new SELECT * FROM servers;

DROP TABLE servers;
ALTER TABLE servers_new RENAME TO servers;

PRAGMA foreign_keys=ON;
