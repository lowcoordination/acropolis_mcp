-- Approval workflows for policy-shaped mutations (enterprise #9, issue #10).
--
-- Four-eyes change control: an operator PROPOSES a policy change, a DIFFERENT admin approves
-- it, and only then does it apply. Opt-in via the `approvals_enabled` setting (default false) —
-- when disabled this table stays empty forever and every write path is byte-identical to
-- before the feature existed (the standing regression pattern of this epic).
--
-- Proposals persist INTENT, not a frozen diff: `payload` stores the requested change (the new
-- desired state) plus a BASELINE snapshot of the target's state at proposal time. The approve
-- path RE-COMPUTES the change against CURRENT state and applies only if it still means what the
-- approver saw — if intervening mutations altered the baseline, approval fails with a "state
-- changed, re-review" error instead of blindly applying a stale write. This is the exact TOCTOU
-- lesson from the GitOps SSRF fix (re-validate at use time, never trust the cached artifact);
-- see docs/approvals.md for the full design.
--
-- Identity: four-eyes means proposer != approver, enforced on USER ID (proposer_user_id vs
-- resolver_user_id), not role. An admin's own proposal needs a DIFFERENT admin; a non-admin
-- proposer's proposal needs an admin, and since roles are single-valued that is automatically a
-- different person. The *_user_id columns are plain INTEGERs with NO FK to users — deliberately,
-- mirroring admin_events.actor's free-text discipline: deleting a user must not delete (or be
-- blocked by) their proposals, which are audit-relevant history. The parallel *_actor TEXT
-- columns carry Principal.actor (username, or the 'admin-token'/'admin-session' fallback labels
-- for the two auth paths with no users row — see archon/admin_auth.py) so the identity reads
-- correctly even after a user is deleted. When proposer_user_id is NULL (break-glass auth), the
-- four-eyes comparison falls back to the actor strings — which means an admin-token proposal can
-- only ever be approved by a REAL user, the four-eyes spirit applied to credentials that must
-- not approve their own or each other's work.
--
-- State machine: pending -> approved | rejected | expired. Transitions out of 'pending' are
-- enforced with UPDATE ... WHERE state = 'pending' (compare-and-swap) in ProposalRepo.resolve,
-- so two concurrent approvers cannot both resolve the same proposal — the first one wins, the
-- second sees an already-resolved row and gets a clear error. `resolved_at` is NULL while
-- pending; `resolver`/`resolver_user_id`/`resolution_reason` are NULL until resolution.

CREATE TABLE IF NOT EXISTS proposals (
    id                INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    target_type       TEXT NOT NULL,       -- 'server_policy' | 'config_import'
    target_id         TEXT NOT NULL,       -- server slug for policies, 'config' for imports
    payload           JSONB NOT NULL,      -- intent: {"request": ..., "baseline": ...}
    proposer_user_id  INTEGER,             -- NULL for admin-token/legacy actors; NO FK (see above)
    proposer          TEXT NOT NULL,       -- Principal.actor at proposal time
    state             TEXT NOT NULL DEFAULT 'pending',  -- pending | approved | rejected | expired
    created_at        TEXT NOT NULL,       -- utcnow() isoformat, same shape as every other ts
    resolved_at       TEXT,
    resolver_user_id  INTEGER,
    resolver          TEXT,
    resolution_reason TEXT
);

CREATE INDEX IF NOT EXISTS idx_proposals_state ON proposals(state, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_proposals_created ON proposals(created_at);
