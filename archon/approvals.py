"""Approval workflows (enterprise #9, issue #10) — four-eyes change control.

The service layer between archon/api.py's routes and db/repo.py's ProposalRepo. It owns the
two things that make this feature more than a "queue + approve" CRUD:

  1. **Proposals persist INTENT, approval re-computes the PLAN.** A proposal stores the
     requested change plus a BASELINE snapshot of the target's state at proposal time (see
     0011_proposals.sql's header). approve() re-computes against CURRENT state and applies only
     if nothing drifted — intervening mutations make the approval fail with a
     "state changed, re-review" error instead of blindly applying a stale write. This is the
     exact TOCTOU lesson from the GitOps SSRF fix (re-validate at use time, never trust the
     cached artifact); the staleness test is the most important test in the feature.

  2. **Four-eyes on identity, not role.** proposer != approver, enforced on user id
     (falling back to actor string for the admin-token/legacy paths that have no users row).
     See _identity() and the plan's "an admin's own proposal still needs a different admin".

Every dependency is Optional-with-graceful-degradation the same way the router treats its own
Optionals: admin_event_repo / tools_cache / webhook_dispatcher / project_repo are all None in
some test constructions, and each no-ops when absent.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from archon.admin_auth import Principal
from archon.admin_audit import record, record_config_import, record_policy_change
from archon.config_io import _policy_diff, export_config, plan_import
from db.models import ServerPolicy
from db.repo import (
    AdminEventRepo,
    ProjectRepo,
    ProposalNotFoundError,
    ProposalRecord,
    ProposalRepo,
    ServerNotFoundError,
    ServerRepo,
    SettingsRepo,
)

logger = logging.getLogger("archon.approvals")

# Settings keys. Mirrored in archon/api.py's _SETTINGS_DEFAULTS (which is what makes them
# editable via the Settings page) and in docs/approvals.md. Kept here too so the service can be
# unit-tested and reasoned about without the router.
SETTING_ENABLED = "approvals_enabled"
SETTING_TTL_DAYS = "approvals_ttl_days"

TARGET_SERVER_POLICY = "server_policy"
TARGET_CONFIG_IMPORT = "config_import"

# Human actor label for the expiry sweep's transitions (see ProposalRepo.expire_due) — the one
# resolution with no human principal; the audit trail still gets an attributable label.
EXPIRY_ACTOR = "expiry-sweep"

# TTL fallback when the setting is absent or unparseable — matches the default written into
# _SETTINGS_DEFAULTS (7 days, per the plan's "TTL, default 7 days").
DEFAULT_TTL_DAYS = 7


class ProposalError(Exception):
    """Base class for approval-service errors; archon/api.py translates each subclass to the
    HTTP status the plan's verification section names."""


class ProposalStaleError(ProposalError):
    """The target's state changed after the proposal was created — the approval must be
    re-reviewed rather than blindly applied (the TOCTOU guard, see module docstring)."""


class ProposalResolvedError(ProposalError):
    """The proposal is no longer pending (already approved/rejected/expired), or a concurrent
    approver won the pending->approved transition first."""


class ProposalConflictError(ProposalError):
    """Four-eyes violated: the resolver is the proposer (same user id, or same actor for the
    no-users-row auth paths)."""


def _identity(principal: Principal) -> tuple:
    """Effective identity for the four-eyes comparison: (user_id, actor).

    user_id is None for the admin-token / legacy-admin paths (no users row — see Principal's
    docstring in archon/admin_auth.py). For those, the actor string IS the identity:
    'admin-token' is always the same actor, so an admin-token proposer can never approve its
    own (or another admin-token's) proposal — only a real user can, which is the four-eyes
    spirit applied to credentials that must not rubber-stamp each other. A real user named
    'admin-token' is still distinct ((user_id, actor) != (None, 'admin-token'))."""
    return (principal.user_id, principal.actor)


def _serialize_policy(policy: ServerPolicy) -> dict[str, Any]:
    """Baseline/request snapshot of a policy. Policies carry tool names, modes, and DLP pattern
    TEXT — operator-authored configuration, the same trust level admin_audit.py already records
    in full (never matched VALUES, which live only in argus/dlp.py at runtime)."""
    return policy.model_dump()


class ApprovalService:
    """Implements propose -> approve/reject/expire for policy-shaped mutations.

    Constructed once per app, inside build_control_plane_router when a ProposalRepo is wired
    (see argus/app.py). The enabled/disabled decision is read from the settings TABLE on every
    call (DB-is-authoritative, same pattern as Pipeline._current_auth_mode and the webhook
    dispatcher) — flipping the Settings-page toggle takes effect immediately, no restart.
    """

    def __init__(
        self,
        *,
        proposal_repo: ProposalRepo,
        server_repo: ServerRepo,
        settings_repo: SettingsRepo,
        admin_event_repo: Optional[AdminEventRepo] = None,
        project_repo: Optional[ProjectRepo] = None,
        tools_cache=None,
        webhook_dispatcher=None,
    ):
        self._proposal_repo = proposal_repo
        self._server_repo = server_repo
        self._settings_repo = settings_repo
        self._admin_event_repo = admin_event_repo
        self._project_repo = project_repo
        self._tools_cache = tools_cache
        self._webhook_dispatcher = webhook_dispatcher

    # ─── gate ────────────────────────────────────────────────────────────────────────────────

    async def enabled(self) -> bool:
        return await self._settings_repo.get(SETTING_ENABLED) == "true"

    # ─── propose ─────────────────────────────────────────────────────────────────────────────

    async def propose_policy_change(
        self,
        *,
        server_slug: str,
        requested: dict[str, Any],
        proposer: Principal,
        client_ip: Optional[str],
    ) -> ProposalRecord:
        """Queue a policy write as a proposal. `requested` is the PolicyUpdateRequest's
        model_dump — the DESIRED new policy state. Validated at propose time (not approve time)
        so a bad payload fails with a 400 here rather than a confusing mid-approval failure."""
        # Validate the intent NOW — ServerPolicy(**requested) raises on bad shapes exactly the
        # way the direct-write path would, keeping "propose" and "apply" equally strict.
        ServerPolicy(**requested)
        try:
            server = await self._server_repo.get(server_slug)
        except ServerNotFoundError:
            raise ProposalError(f"server '{server_slug}' not found")

        baseline = _serialize_policy(await self._server_repo.get_policy(server.id))
        payload = json.dumps({"request": requested, "baseline": baseline}, sort_keys=True)
        proposal = await self._proposal_repo.create(
            target_type=TARGET_SERVER_POLICY,
            target_id=server_slug,
            payload=payload,
            proposer_user_id=proposer.user_id,
            proposer=proposer.actor,
            # Remediation (review 2026-08-10): a server_policy proposal is scoped to its
            # target server's project — this is what lets /proposals* gate on
            # require_project_role instead of global require_role("admin"). See
            # 0012_proposals_project_scope.sql's header for the full rationale.
            project_id=server.project_id,
        )
        await self._record_event(
            proposal, proposer, client_ip,
            action="proposal.create",
            summary=f"proposed policy change on '{server_slug}'",
        )
        await self._notify_pending(proposal)
        return proposal

    async def propose_config_import(
        self,
        *,
        yaml_text: str,
        proposer: Principal,
        client_ip: Optional[str],
    ) -> ProposalRecord:
        """Queue a config import as a proposal. The baseline is a credential-free STABLE export
        snapshot; on approve it is re-exported and compared, so an intervening config change by
        ANY path (direct writes included) fails the approval as stale."""
        # Dry-run the file first so a malformed/unknown-slug YAML fails at PROPOSE time (same
        # never-half-apply discipline as plan_import itself) — an approver must not be handed a
        # proposal whose file was broken from the start.
        plan = await plan_import(
            self._server_repo, self._settings_repo, yaml_text, apply=False,
            project_repo=self._project_repo,
        )
        if not plan.ok:
            raise ProposalError("; ".join(plan.errors))

        baseline = await self._export_snapshot()
        payload = json.dumps(
            {"request": {"yaml": yaml_text}, "baseline": baseline}, sort_keys=True
        )
        proposal = await self._proposal_repo.create(
            target_type=TARGET_CONFIG_IMPORT,
            target_id="config",
            payload=payload,
            proposer_user_id=proposer.user_id,
            proposer=proposer.actor,
            # Remediation (review 2026-08-10): explicitly None, not omitted — a config import
            # can touch servers across every project in one file, so it stays instance-wide
            # and global-admin-gated. Written out at the call site (rather than relying on
            # create()'s default) so the asymmetry with propose_policy_change above is visible
            # here, not just implied by absence.
            project_id=None,
        )
        await self._record_event(
            proposal, proposer, client_ip,
            action="proposal.create",
            summary=f"proposed config import ({len(plan.actions)} change(s))",
        )
        await self._notify_pending(proposal)
        return proposal

    # ─── view (recomputed preview, never a stale stored diff) ───────────────────────────────

    async def preview(self, proposal: ProposalRecord) -> tuple[list[str], bool]:
        """Recompute the proposal's plan against CURRENT state.

        Returns (deltas, stale): the human-readable change list the approver should see RIGHT
        NOW, and whether the target drifted since proposal creation (if stale, approve() will
        refuse — the preview tells the operator before they click). This is the "approval
        re-computes the plan" design made visible: the detail view can never show a plan that
        differs from what approve() will apply.
        """
        payload = proposal.parse_payload()
        if proposal.target_type == TARGET_SERVER_POLICY:
            requested = ServerPolicy(**payload["request"])
            baseline = payload["baseline"]
            try:
                server = await self._server_repo.get(proposal.target_id)
            except ServerNotFoundError:
                return [f"server '{proposal.target_id}' no longer exists"], True
            current = await self._server_repo.get_policy(server.id)
            return _policy_diff(current, requested), _serialize_policy(current) != baseline

        if proposal.target_type == TARGET_CONFIG_IMPORT:
            plan = await plan_import(
                self._server_repo, self._settings_repo, payload["request"]["yaml"],
                apply=False, project_repo=self._project_repo,
            )
            deltas = [a.describe() for a in plan.actions]
            if plan.warnings:
                deltas += [f"warning: {w}" for w in plan.warnings]
            if plan.errors:
                deltas = [f"error: {e}" for e in plan.errors]
            current_export = await self._export_snapshot()
            return deltas, current_export != payload["baseline"]

        return [f"unknown proposal kind {proposal.target_type!r}"], True

    # ─── approve / reject / expire ───────────────────────────────────────────────────────────

    async def approve(
        self,
        *,
        proposal_id: int,
        principal: Principal,
        reason: Optional[str],
        client_ip: Optional[str],
    ) -> ProposalRecord:
        """Approve a pending proposal: four-eyes check, recompute, apply, transition.

        Ordering is deliberate: the staleness check happens BEFORE any write; the apply happens
        BEFORE the pending->approved compare-and-swap. The apply is idempotent (setting a policy
        to the same value, or re-importing an already-imported config), so if a concurrent
        approver wins the CAS, the loser's duplicate apply is a harmless no-op and it sees the
        clear "already resolved" error — the alternative order (CAS then apply) has a crash
        window where a proposal reads approved but nothing was applied, which is worse.
        """
        proposal = await self._proposal_repo.get(proposal_id)
        if proposal.state != "pending":
            raise ProposalResolvedError(
                f"proposal {proposal_id} is already {proposal.state}, not pending"
            )
        if _identity(principal) == (proposal.proposer_user_id, proposal.proposer):
            raise ProposalConflictError(
                "four-eyes: the proposer cannot approve their own proposal"
            )

        payload = proposal.parse_payload()
        if proposal.target_type == TARGET_SERVER_POLICY:
            applied = await self._apply_policy_proposal(
                proposal, payload, principal, client_ip
            )
        elif proposal.target_type == TARGET_CONFIG_IMPORT:
            applied = await self._apply_import_proposal(
                proposal, payload, principal, client_ip
            )
        else:
            raise ProposalError(f"unknown proposal kind {proposal.target_type!r}")

        resolved = await self._proposal_repo.resolve(
            proposal_id, state="approved",
            resolver_user_id=principal.user_id, resolver=principal.actor,
            resolution_reason=reason,
        )
        if resolved is None:
            # A concurrent approver won the compare-and-swap between our apply and this resolve
            # (or the row vanished) — the change is applied either way; report the conflict.
            raise ProposalResolvedError(
                f"proposal {proposal_id} was already resolved by a concurrent approval"
            )

        await self._record_event(
            resolved, principal, client_ip,
            action="proposal.approve",
            summary=f"approved {applied['summary']}"
            + (f" — {reason}" if reason else ""),
        )
        return resolved

    async def reject(
        self,
        *,
        proposal_id: int,
        principal: Principal,
        reason: Optional[str],
        client_ip: Optional[str],
    ) -> ProposalRecord:
        """Reject a pending proposal. NOTE: four-eyes does NOT apply here — withdrawing one's
        own proposal is legitimate (it is the proposer retracting their request), unlike
        self-approval. Reject is admin-gated at the route layer."""
        proposal = await self._proposal_repo.get(proposal_id)
        if proposal.state != "pending":
            raise ProposalResolvedError(
                f"proposal {proposal_id} is already {proposal.state}, not pending"
            )
        resolved = await self._proposal_repo.resolve(
            proposal_id, state="rejected",
            resolver_user_id=principal.user_id, resolver=principal.actor,
            resolution_reason=reason,
        )
        if resolved is None:
            raise ProposalResolvedError(
                f"proposal {proposal_id} was already resolved by a concurrent action"
            )
        await self._record_event(
            resolved, principal, client_ip,
            action="proposal.reject",
            summary=f"rejected proposal {proposal_id} for '{proposal.target_id}'"
            + (f" — {reason}" if reason else ""),
        )
        return resolved

    async def expire_due(self) -> int:
        """TTL sweep: expire pending proposals older than the approvals_ttl_days setting
        (default 7). <= 0 means keep forever. Called by stoa/proposals.py's ProposalExpiryJob on
        the retention-job interval pattern; also directly unit-testable."""
        raw = await self._settings_repo.get(SETTING_TTL_DAYS)
        try:
            days = int(raw) if raw is not None else DEFAULT_TTL_DAYS
        except ValueError:
            days = DEFAULT_TTL_DAYS
        if days <= 0:
            return 0

        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        expired = await self._proposal_repo.expire_due(cutoff)
        if expired and self._admin_event_repo is not None:
            # ONE event for the whole sweep, not one per proposal — a routine TTL pass must not
            # drown the audit log (same rationale as record_config_import's single-event shape).
            await record(
                self._admin_event_repo,
                action="proposal.expire",
                summary=f"expired {expired} stale proposal(s) after {days} day TTL",
                actor=EXPIRY_ACTOR,
                target_type="proposal",
            )
        if expired:
            logger.info("approvals: expired %d stale proposal(s) after %d day TTL", expired, days)
        return expired

    # ─── internals ───────────────────────────────────────────────────────────────────────────

    async def _apply_policy_proposal(
        self,
        proposal: ProposalRecord,
        payload: dict,
        principal: Principal,
        client_ip: Optional[str],
    ) -> dict[str, str]:
        requested_policy = ServerPolicy(**payload["request"])
        baseline = payload["baseline"]
        try:
            server = await self._server_repo.get(proposal.target_id)
        except ServerNotFoundError:
            raise ProposalStaleError(
                f"server '{proposal.target_id}' no longer exists — proposal {proposal.id} "
                "cannot be applied; re-review"
            )
        current = await self._server_repo.get_policy(server.id)
        if _serialize_policy(current) != baseline:
            raise ProposalStaleError(
                f"policy on '{proposal.target_id}' changed since proposal {proposal.id} was "
                "created; state changed, re-review"
            )

        before = current
        await self._server_repo.set_policy(server.id, requested_policy)
        if self._tools_cache is not None:
            # Same stale-cache rationale as the direct write path in api.py's set_policy.
            await self._tools_cache.invalidate(server.id)
        if self._admin_event_repo is not None:
            await record_policy_change(
                self._admin_event_repo,
                server_slug=proposal.target_id,
                current=before,
                incoming=requested_policy,
                actor=principal.actor,
                client_ip=client_ip,
            )
        return {"summary": f"policy change on '{proposal.target_id}'"}

    async def _apply_import_proposal(
        self,
        proposal: ProposalRecord,
        payload: dict,
        principal: Principal,
        client_ip: Optional[str],
    ) -> dict[str, str]:
        baseline = payload["baseline"]
        current_export = await self._export_snapshot()
        if current_export != baseline:
            raise ProposalStaleError(
                f"configuration changed since proposal {proposal.id} was created; "
                "state changed, re-review"
            )

        plan = await plan_import(
            self._server_repo, self._settings_repo, payload["request"]["yaml"],
            apply=True, project_repo=self._project_repo,
        )
        if not plan.ok:
            # Unreachable via the propose path (the file was dry-run there), but a state change
            # between the snapshot comparison and this write could in principle surface a new
            # error — refuse rather than half-apply, same never-half-apply discipline.
            raise ProposalStaleError("; ".join(plan.errors))
        if self._admin_event_repo is not None:
            await record_config_import(
                self._admin_event_repo,
                actions=[a.describe(applied=True) for a in plan.actions],
                actor=principal.actor,
                client_ip=client_ip,
            )
        return {"summary": f"config import ({len(plan.actions)} change(s))"}

    async def _export_snapshot(self) -> str:
        """Credential-free stable export used as import-proposal baselines (see
        config_io.ExportResult.to_stable_yaml — strips exported_at so a re-export of unchanged
        state is byte-identical, which is what makes the staleness comparison meaningful)."""
        result = await export_config(
            self._server_repo, self._settings_repo,
            include_credentials=False, project_repo=self._project_repo,
        )
        return result.to_stable_yaml()

    async def _record_event(
        self,
        proposal: ProposalRecord,
        principal: Principal,
        client_ip: Optional[str],
        *,
        action: str,
        summary: str,
    ) -> None:
        """Write a control-plane admin event for a proposal lifecycle transition. Both
        identities (proposer and resolver) are present on resolution events: the proposal row
        itself is carried in `after`, and the resolver's identity is the event's `actor`."""
        if self._admin_event_repo is None:
            return
        await record(
            self._admin_event_repo,
            action=action,
            summary=summary,
            actor=principal.actor,
            target_type="proposal",
            target_id=str(proposal.id),
            after={
                "target_type": proposal.target_type,
                "target_id": proposal.target_id,
                "state": proposal.state,
                "proposer": proposal.proposer,
                "resolver": proposal.resolver,
                "resolved_at": proposal.resolved_at,
            },
            client_ip=client_ip,
        )

    async def _notify_pending(self, proposal: ProposalRecord) -> None:
        """Fire the approval_pending webhook (when configured). No diff contents, no payload —
        consistent with the codebase's webhook secrecy discipline (same reason `blocked` events
        exclude args_summary and DLP never sends matched values)."""
        if self._webhook_dispatcher is None:
            return
        await self._webhook_dispatcher.notify_approval_pending(
            proposal_id=proposal.id,
            target_type=proposal.target_type,
            target_id=proposal.target_id,
            proposer=proposal.proposer,
        )
