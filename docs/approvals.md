# Approval workflows (four-eyes change control)

Enterprise #9 (issue #10): policy and config-import changes can require a **second identity's
approval** before they apply. **Off by default** — a gateway that never enables this behaves
byte-identically to before the feature existed.

## GitOps vs. in-app approvals — read this first

This feature deliberately does **not** compete with [policy-as-code / GitOps](policy-cookbook.md).
The decision table:

| Deployment style | Change path | Four-eyes mechanism |
|---|---|---|
| GitOps adopted | Files in a git repo, reconciled by the gateway | **Pull-request review** (branch protection, required reviewers, CODEOWNERS). This is strictly better than anything in-app — leave approvals OFF. |
| No GitOps (UI/API-driven, most homelabs and many teams) | Operator edits a policy in the UI, or imports config | **In-app approvals** (this feature): the change queues as a proposal; a second admin approves. |

The rule of thumb: **if your changes go through git, use PR review; if they go through the UI,
use approvals. Never enable both blindly** — an instance with GitOps reconcile enabled should
leave `approvals_enabled` off, or a reconcile can drift a pending proposal's target and every
approval will fail the staleness guard (which is the guard working, not a bug — see below).

## What it does

With `approvals_enabled` on (Settings → *Require approval for policy and config changes*):

- `PUT /api/v1/servers/{slug}/policy` (policy edits, including DLP config) returns **202 +
  `{proposal_id}`** instead of applying. Nothing changes server-side.
- `POST /api/v1/config/import` with `apply: true` returns **202 + `{proposal_id}`** instead of
  importing. Dry-run previews (`apply: false`) are unchanged — a preview changes nothing.
- The proposal is visible under **Approvals** in the UI (admin only), with the plan
  **recomputed against current state** every time it's viewed — never a stored stale diff.
- A **different admin** approves or rejects it (four-eyes is enforced on user identity, not
  role; an admin's own proposal needs a different admin, and an admin-token/break-glass
  proposal can only be approved by a real user).
- On approval, the change applies **only if the target hasn't drifted** since the proposal was
  created; otherwise it's refused with `state changed, re-review` (HTTP 409).
- Pending proposals expire after `approvals_ttl_days` (default 7); expired proposals cannot be
  approved.
- Every transition (`proposal.create` / `proposal.approve` / `proposal.reject` /
  `proposal.expire`) writes a control-plane admin event carrying **both identities** (proposer
  and resolver).

### Scope — deliberately narrow

Only **policy-shaped mutations** go through approvals: per-server policy edits (which include
DLP config), and config import. Server CRUD, API keys, user management, and settings stay
direct-with-audit — gating everything would turn the gateway into a ticketing system. There are
no approval chains, no per-project approvers, and no email notifications (webhook + UI badge
only).

### Why "intent, not a frozen diff"

A proposal stores the **requested change**, not a diff to blindly replay. Approval re-computes
the plan against current state and applies it only if it still means what the approver saw —
intervening changes make the approval fail instead of silently applying a stale write. This is
the same re-validate-at-use-time lesson as the GitOps SSRF fix: **never trust the cached
artifact.**

## API

All proposal routes are **global-admin-only** (they expose full policy intent / import YAML,
which can include plaintext credentials):

| Route | Purpose |
|---|---|
| `GET /api/v1/proposals?state=pending` | List (filter: `pending`, `approved`, `rejected`, `expired`) |
| `GET /api/v1/proposals/{id}` | Detail + recomputed preview + `stale` flag |
| `POST /api/v1/proposals/{id}/approve` | Approve (`{"reason": "..."}` optional) |
| `POST /api/v1/proposals/{id}/reject` | Reject (`{"reason": "..."}` optional) |

Error mapping: four-eyes violation → **403** with a distinct message; state changed →
**409** `state changed, re-review`; already resolved → **409**.

## Webhooks

Enable the `approval_pending` event in Settings → Alerts to be notified when a proposal is
created. The payload carries only handles — `proposal_id`, `target_type`, `target_id`,
`proposer` — **never** diff contents, policy payloads, or YAML (the same secrecy discipline as
`blocked` events excluding `args_summary`).

## Settings

| Setting | Default | Meaning |
|---|---|---|
| `approvals_enabled` | `false` | Master switch (Settings page / `ACROPOLIS_`-free settings table) |
| `approvals_ttl_days` | `7` | How long a pending proposal lives before the sweep expires it |

Both are exported/imported with config exports and recorded in the control-plane audit log like
any other setting.
