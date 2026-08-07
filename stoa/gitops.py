"""GitOps / policy-as-code — drift detection between live config and a git-tracked file.

Advisory model: Acropolis polls a configured git/HTTPS source, computes the same ImportPlan
diff the CLI's `check` command produces, and surfaces drift (UI banner, /metrics gauge, webhook).
Applying stays a deliberate action (POST /api/v1/config/reconcile or `argus import-config --apply`).

SECURITY: This is an outbound-fetch feature. The configured URL is validated with the same
strict policy as webhook targets (_validate_webhook_url): https-only, no redirects, private
IPs blocked unless explicitly allowed. Fetched content goes through the exact same plan_import
validation as a hand-uploaded file — no "trusted because it came from git" shortcut.
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Optional

import httpx

from archon.config_io import ImportPlan, plan_import
from archon.schemas import _validate_webhook_url
from db.repo import ServerRepo, SettingsRepo

logger = logging.getLogger("stoa.gitops")

# Poll interval for checking drift. Same order of magnitude as health polling.
DEFAULT_POLL_SECONDS = 300.0  # 5 minutes

# Timeout for fetching the config file. Short — this is a background poll, not a user request.
FETCH_TIMEOUT_SECONDS = 10.0


@dataclass
class DriftState:
    """Current drift state, cached between polls."""
    status: str = "unknown"  # "in_sync" | "drifted" | "unknown" | "error"
    plan: Optional[ImportPlan] = None
    last_check: Optional[float] = None
    last_error: Optional[str] = None
    commit_sha: Optional[str] = None  # populated when source is a git ref


class ConfigSource:
    """Polls a configured git/HTTPS source and computes drift against live state.

    Settings (read live from SettingsRepo on every poll):
        gitops_enabled        — "true" to enable polling
        gitops_url            — HTTPS URL to the config file (raw file, not a git clone)
        gitops_ref            — optional git ref for provenance (commit SHA recorded in audit)
        gitops_path           — path within the repo (for URL construction)
        gitops_poll_seconds   — override poll interval
        gitops_allow_private  — "true" to allow private/LAN URLs (default: blocked)

    The URL is validated on every poll with _validate_webhook_url's strict policy.
    """

    def __init__(
        self,
        server_repo: ServerRepo,
        settings_repo: SettingsRepo,
        http_client: Optional[httpx.AsyncClient] = None,
    ):
        self._server_repo = server_repo
        self._settings_repo = settings_repo
        self._http = http_client or httpx.AsyncClient(
            timeout=FETCH_TIMEOUT_SECONDS, follow_redirects=False
        )
        self._owns_http = http_client is None
        self._state = DriftState()
        self._task: Optional[asyncio.Task] = None
        self._webhook_dispatcher = None  # set by app.py if webhooks enabled

    def set_webhook_dispatcher(self, dispatcher) -> None:
        """Wire in the webhook dispatcher for drift events. Called by app.py."""
        self._webhook_dispatcher = dispatcher

    @property
    def state(self) -> DriftState:
        return self._state

    async def start(self) -> None:
        if self._task is None:
            self._task = asyncio.create_task(self._poll_loop())

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            try:
                await asyncio.wait_for(self._task, timeout=5.0)
            except asyncio.CancelledError:
                pass
            except asyncio.TimeoutError:
                logger.warning("gitops poll task did not stop within 5s; abandoning it")
            self._task = None
        if self._owns_http:
            await self._http.aclose()

    async def _poll_loop(self) -> None:
        while True:
            try:
                await self.check_once()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("gitops poll iteration failed")
                self._state.status = "error"
                self._state.last_error = "poll iteration failed"

            interval = await self._get_poll_interval()
            await asyncio.sleep(interval)

    async def _get_poll_interval(self) -> float:
        raw = await self._settings_repo.get("gitops_poll_seconds")
        try:
            return float(raw) if raw is not None else DEFAULT_POLL_SECONDS
        except ValueError:
            return DEFAULT_POLL_SECONDS

    async def check_once(self) -> DriftState:
        """Run one drift check. Updates self._state and returns it."""
        enabled = await self._settings_repo.get("gitops_enabled")
        if enabled != "true":
            self._state.status = "unknown"
            self._state.last_check = time.time()
            return self._state

        url = await self._settings_repo.get("gitops_url")
        if not url:
            self._state.status = "unknown"
            self._state.last_check = time.time()
            self._state.last_error = "gitops_url not configured"
            return self._state

        # SSRF validation: same strict policy as webhook targets
        allow_private = (await self._settings_repo.get("gitops_allow_private")) == "true"
        try:
            _validate_webhook_url(url, allow_private=allow_private)
        except ValueError as e:
            self._state.status = "error"
            self._state.last_check = time.time()
            self._state.last_error = f"invalid gitops_url: {e}"
            return self._state

        # Fetch the config file
        try:
            response = await self._http.get(url)
            response.raise_for_status()
            yaml_text = response.text
        except httpx.HTTPError as e:
            self._state.status = "error"
            self._state.last_check = time.time()
            self._state.last_error = f"fetch failed: {e}"
            return self._state

        # Compute drift using the same plan_import as a hand-uploaded file
        try:
            plan = await plan_import(
                self._server_repo, self._settings_repo, yaml_text, apply=False
            )
        except Exception as e:
            self._state.status = "error"
            self._state.last_check = time.time()
            self._state.last_error = f"plan computation failed: {e}"
            return self._state

        # Determine drift status
        if not plan.ok:
            self._state.status = "error"
            self._state.last_error = "; ".join(plan.errors)
        else:
            drift_actions = [a for a in plan.actions if a.kind != "unchanged"]
            if drift_actions:
                self._state.status = "drifted"
                self._state.plan = plan
                # Fire webhook on drift (debounced by dispatcher)
                if self._webhook_dispatcher is not None:
                    await self._webhook_dispatcher.fire(
                        "drift",
                        {
                            "status": "drifted",
                            "changes": len(drift_actions),
                            "summary": "; ".join(a.describe(applied=False) for a in drift_actions[:3]),
                        },
                    )
            else:
                self._state.status = "in_sync"
                self._state.plan = None

        self._state.last_check = time.time()
        return self._state

    async def reconcile(self) -> ImportPlan:
        """Apply the pending plan (if any). Returns the applied plan.

        This is the explicit apply step — the human (or CI) has seen the drift and chosen to
        reconcile. The same plan_import computes and applies in one call.
        """
        if self._state.plan is None:
            raise ValueError("no pending plan to reconcile")

        # Re-fetch to get the current file content (don't trust cached plan)
        url = await self._settings_repo.get("gitops_url")
        if not url:
            raise ValueError("gitops_url not configured")

        response = await self._http.get(url)
        response.raise_for_status()
        yaml_text = response.text

        # Apply with apply=True
        plan = await plan_import(
            self._server_repo, self._settings_repo, yaml_text, apply=True
        )

        # Clear drift state after successful apply
        if plan.ok:
            self._state.status = "in_sync"
            self._state.plan = None

        return plan
