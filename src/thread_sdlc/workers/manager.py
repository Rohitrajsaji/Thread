"""WorkerManager coordinating worktrees, crash reconciliation, RolePolicy, caps, and redacted logs."""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Callable
from pathlib import Path

from pydantic import BaseModel, Field

from thread_sdlc.config.models import PolicyConfig, ScopeConfig
from thread_sdlc.governance.redactor import RedactedLogWriter
from thread_sdlc.state.db import StateDatabase
from thread_sdlc.state.events import EventLogger
from thread_sdlc.state.models import AssignmentRecord, utc_now_iso
from thread_sdlc.state.repositories import StateRepository
from thread_sdlc.workers.adapter import (
    PausedQuota,
    UsageMetrics,
    WorkerAdapter,
    WorkerAssignment,
    WorkerEvent,
    WorkerExecutionError,
)
from thread_sdlc.workers.permissions import RolePolicy
from thread_sdlc.workers.worktree import ReconcileResult, WorktreeManager


class WorkerConcurrencyError(Exception):
    """Raised when ``max_workers_per_thread`` would be exceeded."""


class WorkerRetryLimitError(Exception):
    """Raised when ``max_retries_per_ticket`` is exhausted."""


class DispatchResult(BaseModel):
    """Outcome of ``WorkerManager.dispatch_ticket``."""

    assignment_id: str
    ticket_id: str
    status: str  # "completed" | "reconciled_completed"
    reconciled: bool = False
    worker_invoked: bool = False
    result_sha: str | None = None
    log_path: str | None = None
    usage: UsageMetrics = Field(default_factory=UsageMetrics)
    events: list[WorkerEvent] = Field(default_factory=list)


class WorkerManager:
    """Orchestrates ticket execution, reconciliation, quota caps, and redacted logging."""

    def __init__(
        self,
        *,
        repo_root: Path,
        db: StateDatabase,
        policy: PolicyConfig,
        scope: ScopeConfig,
        adapter_factory: Callable[[RolePolicy], WorkerAdapter],
        worktree_manager: WorktreeManager | None = None,
    ) -> None:
        self.repo_root = repo_root.resolve()
        self.db = db
        self.repo = StateRepository(db)
        self.events = EventLogger(db)
        self.policy = policy
        self.scope = scope
        self.adapter_factory = adapter_factory
        self.worktree_manager = worktree_manager or WorktreeManager(self.repo_root)

    def reconcile_assignment(self, assignment_id: str) -> ReconcileResult:
        """Check Git history for an existing assignment and reconcile SQLite state idempotently."""
        assignment = self.repo.get_assignment(assignment_id)
        if assignment is None:
            raise KeyError(f"Assignment {assignment_id!r} not found")

        ticket = self.repo.get_ticket(assignment.ticket_id)
        if ticket is None:
            raise KeyError(f"Ticket {assignment.ticket_id!r} not found for assignment {assignment_id!r}")

        if assignment.status in ("completed", "reconciled_completed") and assignment.result_sha:
            return ReconcileResult(
                reconciled=True,
                status=assignment.status,
                assignment_id=assignment.id,
                result_sha=assignment.result_sha,
                branch=ticket.worktree_branch,
                worktree_path=Path(ticket.worktree_path) if ticket.worktree_path else None,
            )

        res = self.worktree_manager.reconcile_assignment(
            ticket.thread_id,
            ticket.id,
            assignment.id,
            base_sha=assignment.base_sha or None,
        )
        if res.reconciled and res.result_sha:
            self.repo.update_assignment(
                assignment.id,
                status="reconciled_completed",
                result_sha=res.result_sha,
                ended_at=utc_now_iso(),
            )
            self.repo.update_ticket(
                ticket.id,
                status="done",
                worktree_branch=res.branch,
                worktree_path=str(res.worktree_path) if res.worktree_path else None,
                result_sha=res.result_sha,
            )
            self.events.emit(
                ticket.thread_id,
                "assignment_reconciled",
                {
                    "assignment_id": assignment.id,
                    "ticket_id": ticket.id,
                    "result_sha": res.result_sha,
                    "branch": res.branch,
                },
            )
        return res

    def reconcile_ticket(
        self,
        thread_id: str,
        ticket_id: str,
        assignment_id: str | None = None,
    ) -> ReconcileResult | None:
        """Reconcile the latest (or specified) assignment for ``ticket_id`` before dispatch."""
        target_assignment_id = assignment_id
        existing = self.repo.get_assignment(assignment_id) if assignment_id else None

        if existing is not None:
            res = self.reconcile_assignment(existing.id)
            if res.reconciled and res.result_sha:
                return res

        latest = self.repo.get_latest_assignment_for_ticket(ticket_id)
        if latest is not None and (existing is None or latest.id != existing.id):
            latest_res = self.reconcile_assignment(latest.id)
            if latest_res.reconciled and latest_res.result_sha:
                return latest_res
            if existing is None and target_assignment_id is None:
                return latest_res

        if existing is not None:
            return res

        if target_assignment_id is None:
            return None

        ticket = self.repo.get_ticket(ticket_id)
        if ticket is None:
            raise KeyError(f"Ticket {ticket_id!r} not found")

        res = self.worktree_manager.reconcile_assignment(
            thread_id, ticket_id, target_assignment_id
        )
        if res.reconciled and res.result_sha:
            now = utc_now_iso()
            self.repo.create_assignment(
                AssignmentRecord(
                    id=target_assignment_id,
                    ticket_id=ticket_id,
                    adapter_type="reconciled",
                    status="reconciled_completed",
                    base_sha="",
                    result_sha=res.result_sha,
                    commit_trailer=self.worktree_manager.commit_trailer(target_assignment_id),
                    started_at=now,
                    ended_at=now,
                )
            )
            self.repo.update_ticket(
                ticket_id,
                status="done",
                worktree_branch=res.branch,
                worktree_path=str(res.worktree_path) if res.worktree_path else None,
                result_sha=res.result_sha,
            )
            self.events.emit(
                thread_id,
                "assignment_reconciled",
                {
                    "assignment_id": target_assignment_id,
                    "ticket_id": ticket_id,
                    "result_sha": res.result_sha,
                    "branch": res.branch,
                },
            )
        return res

    def _pause_for_quota(
        self,
        *,
        thread_id: str,
        assignment_id: str,
        pq: PausedQuota,
        credits_delta: float,
        turns_delta: int,
    ) -> None:
        self.repo.update_assignment(
            assignment_id,
            status="paused_quota",
            turns_used=turns_delta,
            credits_used=credits_delta,
            ended_at=utc_now_iso(),
        )
        self.repo.increment_thread_usage(
            thread_id, credits_delta=credits_delta, turns_delta=turns_delta
        )
        self.repo.update_thread(thread_id, status="PausedQuota")
        self.events.emit(
            thread_id,
            "quota_paused",
            {
                "assignment_id": assignment_id,
                "limit_type": pq.limit_type,
                "reason": pq.reason,
                "credits_used": pq.credits_used,
                "turns_used": pq.turns_used,
            },
        )

    async def dispatch_ticket(
        self,
        thread_id: str,
        ticket_id: str,
        instructions: str,
        *,
        assignment_id: str | None = None,
        model: str | None = None,
    ) -> DispatchResult:
        """Reconcile any committed prior work, enforce caps, and dispatch a single worker."""
        thread = self.repo.get_thread(thread_id)
        if thread is None:
            raise KeyError(f"Thread {thread_id!r} not found")
        ticket = self.repo.get_ticket(ticket_id)
        if ticket is None:
            raise KeyError(f"Ticket {ticket_id!r} not found")

        # Step 1: Pre-dispatch crash reconciliation (never invoke worker if already committed)
        rec = self.reconcile_ticket(thread_id, ticket_id, assignment_id=assignment_id)
        if rec is not None and rec.reconciled and rec.result_sha:
            return DispatchResult(
                assignment_id=rec.assignment_id or assignment_id or "",
                ticket_id=ticket_id,
                status="reconciled_completed",
                reconciled=True,
                worker_invoked=False,
                result_sha=rec.result_sha,
            )

        # Step 2: Atomically enforce caps and reserve running assignment inside BEGIN IMMEDIATE
        asgn_id = assignment_id or f"asgn-{uuid.uuid4().hex[:12]}"
        log_rel_path = f".thread-state/redacted-logs/{asgn_id}.log"
        trailer = self.worktree_manager.commit_trailer(asgn_id)

        thread, ticket, rejection, meta = self.repo.reserve_running_assignment(
            thread_id=thread_id,
            assignment=AssignmentRecord(
                id=asgn_id,
                ticket_id=ticket_id,
                adapter_type="pending",
                status="running",
                base_sha=thread.base_sha,
                commit_trailer=trailer,
                log_path=log_rel_path,
            ),
            max_workers_per_thread=self.policy.caps.max_workers_per_thread,
            max_retries_per_ticket=self.policy.caps.max_retries_per_ticket,
            max_credits_per_thread=self.policy.caps.max_credits_per_thread,
        )
        if rejection == "paused_quota":
            raise PausedQuota(
                f"Thread {thread_id} has exhausted credit budget "
                f"({thread.credits_used}/{self.policy.caps.max_credits_per_thread})",
                limit_type="credits",
                credits_used=thread.credits_used,
                turns_used=thread.turns_used,
            )
        if rejection == "concurrency_limit":
            active_workers = meta.get("active_workers", self.policy.caps.max_workers_per_thread)
            raise WorkerConcurrencyError(
                f"Active workers ({active_workers}) reached max_workers_per_thread "
                f"({self.policy.caps.max_workers_per_thread})"
            )
        if rejection == "retry_limit":
            raise WorkerRetryLimitError(
                f"Ticket {ticket_id} exceeded max_retries_per_ticket "
                f"({self.policy.caps.max_retries_per_ticket})"
            )
        if rejection == "duplicate_assignment":
            raise WorkerConcurrencyError(
                f"Assignment {asgn_id!r} already exists with status {meta.get('existing_status')!r}"
            )

        # Step 3 & 4: Ensure isolated worktree and instantiate adapter; clean up on setup failure
        try:
            base_ref = thread.base_sha or self.policy.base_branch
            worktree = self.worktree_manager.ensure_worktree(
                thread_id, ticket_id, base_ref=base_ref
            )
            role_policy = RolePolicy.from_scope_config(ticket.role, self.scope, worktree.path)
            adapter = self.adapter_factory(role_policy)
            adapter_type = type(adapter).__name__

            self.repo.update_assignment(
                asgn_id,
                adapter_type=adapter_type,
                base_sha=worktree.base_sha,
            )
            self.repo.update_ticket(
                ticket_id,
                status="in_progress",
                worktree_branch=worktree.branch,
                worktree_path=str(worktree.path),
            )
            self.events.emit(
                thread_id,
                "assignment_started",
                {
                    "assignment_id": asgn_id,
                    "ticket_id": ticket_id,
                    "role": ticket.role,
                    "branch": worktree.branch,
                    "adapter": adapter_type,
                },
            )
        except BaseException as exc:
            self.repo.update_assignment(
                asgn_id,
                status="failed",
                ended_at=utc_now_iso(),
            )
            self.repo.update_ticket(ticket_id, status="failed")
            self.events.emit(
                thread_id,
                "assignment_failed",
                {
                    "assignment_id": asgn_id,
                    "ticket_id": ticket_id,
                    "error_type": type(exc).__name__,
                    "error": str(exc) or "Worker setup failed",
                    "phase": "setup",
                },
            )
            raise

        # Step 5: Execute worker with redacted logging and live cap checks
        remaining_credits = max(0.0, self.policy.caps.max_credits_per_thread - thread.credits_used)
        worker_assignment = WorkerAssignment(
            assignment_id=asgn_id,
            thread_id=thread_id,
            ticket_id=ticket_id,
            role=ticket.role,
            instructions=instructions,
            worktree_path=worktree.path,
            base_sha=worktree.base_sha,
            max_turns=self.policy.caps.max_turns_per_assignment,
            max_credits=remaining_credits,
            model=model,
        )

        collected_events: list[WorkerEvent] = []
        log_abs_path = self.repo_root / log_rel_path
        committed_sha: str | None = None

        try:
            with RedactedLogWriter(log_abs_path) as log_writer:
                await adapter.start(worker_assignment)
                async for evt in adapter.stream_events():
                    collected_events.append(evt)
                    log_writer.write_line(f"[{evt.type}] {evt.message}")
                    self.events.emit(
                        thread_id,
                        f"worker.{evt.type}",
                        {
                            "assignment_id": asgn_id,
                            "ticket_id": ticket_id,
                            "message": evt.message,
                            "data": evt.data,
                        },
                    )
                    if evt.type == "commit" and isinstance(evt.data.get("result_sha"), str):
                        committed_sha = evt.data["result_sha"]

                    usage_now = adapter.usage_metrics()
                    if usage_now.turns_used >= self.policy.caps.max_turns_per_assignment:
                        pq = PausedQuota(
                            f"Turn cap reached ({usage_now.turns_used}/{self.policy.caps.max_turns_per_assignment})",
                            limit_type="turns",
                            credits_used=usage_now.credits_used,
                            turns_used=usage_now.turns_used,
                        )
                        await adapter.abort()
                        raise pq
                    if thread.credits_used + usage_now.credits_used >= self.policy.caps.max_credits_per_thread:
                        pq = PausedQuota(
                            f"Thread credit cap reached ({thread.credits_used + usage_now.credits_used}/{self.policy.caps.max_credits_per_thread})",
                            limit_type="credits",
                            credits_used=thread.credits_used + usage_now.credits_used,
                            turns_used=usage_now.turns_used,
                        )
                        await adapter.abort()
                        raise pq
        except PausedQuota as pq:
            usage_now = adapter.usage_metrics()
            self._pause_for_quota(
                thread_id=thread_id,
                assignment_id=asgn_id,
                pq=pq,
                credits_delta=usage_now.credits_used,
                turns_delta=usage_now.turns_used,
            )
            raise
        except asyncio.CancelledError as exc:
            try:
                await adapter.abort()
            except Exception:
                pass
            finally:
                usage_now = adapter.usage_metrics()
                self.repo.update_assignment(
                    asgn_id,
                    status="failed",
                    turns_used=usage_now.turns_used,
                    credits_used=usage_now.credits_used,
                    ended_at=utc_now_iso(),
                )
                self.repo.increment_thread_usage(
                    thread_id,
                    credits_delta=usage_now.credits_used,
                    turns_delta=usage_now.turns_used,
                )
                self.repo.update_ticket(ticket_id, status="failed")
                self.events.emit(
                    thread_id,
                    "assignment_failed",
                    {
                        "assignment_id": asgn_id,
                        "ticket_id": ticket_id,
                        "error_type": type(exc).__name__,
                        "error": str(exc) or "Worker execution cancelled",
                        "aborted": True,
                        "turns_used": usage_now.turns_used,
                        "credits_used": usage_now.credits_used,
                    },
                )
            raise
        except Exception as exc:
            usage_now = adapter.usage_metrics()
            self.repo.update_assignment(
                asgn_id,
                status="failed",
                turns_used=usage_now.turns_used,
                credits_used=usage_now.credits_used,
                ended_at=utc_now_iso(),
            )
            self.repo.increment_thread_usage(
                thread_id,
                credits_delta=usage_now.credits_used,
                turns_delta=usage_now.turns_used,
            )
            self.repo.update_ticket(ticket_id, status="failed")
            self.events.emit(
                thread_id,
                "assignment_failed",
                {
                    "assignment_id": asgn_id,
                    "ticket_id": ticket_id,
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                    "turns_used": usage_now.turns_used,
                    "credits_used": usage_now.credits_used,
                },
            )
            raise
        finally:
            await adapter.disconnect()

        # Step 6: Verify commit SHA & finalize DB state
        usage_final = adapter.usage_metrics()
        git_sha = self.worktree_manager.find_commit_by_assignment_id(
            asgn_id, worktree.path, base_sha=worktree.base_sha
        )
        result_sha = git_sha or committed_sha

        if usage_final.aborted:
            self.repo.update_assignment(
                asgn_id,
                status="failed",
                turns_used=usage_final.turns_used,
                credits_used=usage_final.credits_used,
                ended_at=utc_now_iso(),
            )
            self.repo.increment_thread_usage(
                thread_id,
                credits_delta=usage_final.credits_used,
                turns_delta=usage_final.turns_used,
            )
            self.repo.update_ticket(ticket_id, status="failed")
            self.events.emit(
                thread_id,
                "assignment_failed",
                {
                    "assignment_id": asgn_id,
                    "ticket_id": ticket_id,
                    "error_type": "WorkerExecutionError",
                    "error": "Worker execution aborted before completion",
                    "aborted": True,
                    "turns_used": usage_final.turns_used,
                    "credits_used": usage_final.credits_used,
                },
            )
            raise WorkerExecutionError("Worker execution aborted before completion")

        self.repo.update_assignment(
            asgn_id,
            status="completed",
            result_sha=result_sha,
            turns_used=usage_final.turns_used,
            credits_used=usage_final.credits_used,
            ended_at=utc_now_iso(),
        )
        self.repo.update_ticket(
            ticket_id,
            status="done",
            worktree_branch=worktree.branch,
            worktree_path=str(worktree.path),
            result_sha=result_sha,
        )
        self.repo.increment_thread_usage(
            thread_id,
            credits_delta=usage_final.credits_used,
            turns_delta=usage_final.turns_used,
        )
        self.events.emit(
            thread_id,
            "assignment_completed",
            {
                "assignment_id": asgn_id,
                "ticket_id": ticket_id,
                "result_sha": result_sha,
                "turns_used": usage_final.turns_used,
                "credits_used": usage_final.credits_used,
            },
        )

        return DispatchResult(
            assignment_id=asgn_id,
            ticket_id=ticket_id,
            status="completed",
            reconciled=False,
            worker_invoked=True,
            result_sha=result_sha,
            log_path=log_rel_path,
            usage=usage_final,
            events=collected_events,
        )
