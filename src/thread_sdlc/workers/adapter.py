"""WorkerAdapter protocol, shared models, PausedQuota, and MockWorkerAdapter."""

from __future__ import annotations

import asyncio
import subprocess
import time
from collections.abc import AsyncIterator, Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, Protocol, runtime_checkable

from pydantic import BaseModel, Field

from thread_sdlc.governance import redactor
from thread_sdlc.workers.permissions import RolePolicy

QUOTA_ERROR_MARKERS = (
    "quota",
    "rate limit",
    "rate_limit",
    "402",
    "429",
    "billing",
    "allowance",
    "insufficient_quota",
    "premium request",
)


class PausedQuota(Exception):
    """Raised cleanly when turns, credits, or provider quota caps are exhausted."""

    def __init__(
        self,
        reason: str,
        *,
        limit_type: Literal["credits", "turns", "workers", "provider_quota"] = "credits",
        credits_used: float = 0.0,
        turns_used: int = 0,
    ) -> None:
        self.reason = reason
        self.limit_type = limit_type
        self.credits_used = credits_used
        self.turns_used = turns_used
        super().__init__(reason)


class WorkerExecutionError(Exception):
    """Raised when a worker subprocess or SDK session fails unexpectedly."""


class AdapterUnavailableError(WorkerExecutionError):
    """Raised when the requested Copilot SDK or CLI runtime is unavailable."""


class WorkerAssignment(BaseModel):
    """Execution context handed to a WorkerAdapter."""

    assignment_id: str
    thread_id: str
    ticket_id: str
    role: str
    instructions: str
    worktree_path: Path
    base_sha: str
    max_turns: int = 30
    max_credits: float = 500.0
    model: str | None = None
    timeout_seconds: float = 600.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class WorkerEvent(BaseModel):
    """Normalized redacted event emitted by a WorkerAdapter."""

    type: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    message: str = ""
    data: dict[str, Any] = Field(default_factory=dict)


class UsageMetrics(BaseModel):
    """Token, turn, and credit accounting for a worker assignment."""

    turns_used: int = 0
    credits_used: float = 0.0
    input_tokens: int = 0
    output_tokens: int = 0
    model: str | None = None
    aborted: bool = False
    duration_ms: float = 0.0


class AdapterProbeResult(BaseModel):
    """Diagnostic availability summary for an adapter backend."""

    adapter_type: Literal["sdk", "cli", "mock"]
    available: bool
    sdk_installed: bool = False
    cli_found: bool = False
    cli_path: str | None = None
    auth_configured: bool = False
    details: str = ""
    blocking_reason: str | None = None


@runtime_checkable
class WorkerAdapter(Protocol):
    """Unified async interface implemented by SDK, CLI, and Mock worker adapters."""

    async def start(self, assignment: WorkerAssignment) -> None: ...

    def stream_events(self) -> AsyncIterator[WorkerEvent]: ...

    async def abort(self) -> None: ...

    async def disconnect(self) -> None: ...

    def usage_metrics(self) -> UsageMetrics: ...


def is_quota_error(text: str) -> bool:
    """Return True if an error message indicates rate-limit / quota exhaustion."""
    lower = text.lower()
    return any(marker in lower for marker in QUOTA_ERROR_MARKERS)


class BaseWorkerAdapter:
    """Shared helper mixin for event secret redaction and cap enforcement."""

    def __init__(self, policy: RolePolicy) -> None:
        self._policy = policy
        self._usage = UsageMetrics()
        self._assignment: WorkerAssignment | None = None
        self._started_at_mono: float | None = None

    def _redact_event(
        self, event_type: str, message: str = "", data: dict[str, Any] | None = None
    ) -> WorkerEvent:
        clean_msg = redactor.redact_text(message)
        clean_data = redactor.redact_payload(data or {})
        return WorkerEvent(type=event_type, message=clean_msg, data=clean_data)

    def _check_caps(self, assignment: WorkerAssignment, usage: UsageMetrics) -> None:
        if usage.turns_used >= assignment.max_turns:
            raise PausedQuota(
                f"Assignment turn cap reached ({usage.turns_used}/{assignment.max_turns})",
                limit_type="turns",
                credits_used=usage.credits_used,
                turns_used=usage.turns_used,
            )
        if usage.credits_used >= assignment.max_credits:
            raise PausedQuota(
                f"Assignment credit cap reached ({usage.credits_used}/{assignment.max_credits})",
                limit_type="credits",
                credits_used=usage.credits_used,
                turns_used=usage.turns_used,
            )

    def usage_metrics(self) -> UsageMetrics:
        if self._started_at_mono is not None and self._usage.duration_ms == 0.0:
            self._usage.duration_ms = (time.monotonic() - self._started_at_mono) * 1000.0
        return self._usage.model_copy()


class MockWorkerAdapter(BaseWorkerAdapter):
    """Deterministic worker adapter for tests, diagnostics, and crash recovery simulations."""

    def __init__(
        self,
        policy: RolePolicy,
        *,
        scenario: Literal[
            "commit_success",
            "crash_after_commit",
            "out_of_scope_write",
            "disallowed_shell",
            "quota_exceeded",
            "slow_for_abort",
            "secret_leak",
            "readonly_review",
        ] = "commit_success",
        target_path: str = ".thread/policy.yaml",
        shell_command: str = "pytest && rm -rf /",
        allowed_file_relpath: str = "app/feature.py",
        allowed_content: str = "def implemented() -> bool:\n    return True\n",
        abort_wait_seconds: float = 10.0,
        commit_message: str = "Implement ticket changes",
        credits_per_turn: float = 1.0,
        quota_mode: Literal["turns", "credits", "provider"] = "turns",
        on_commit_callback: Callable[[str], None] | None = None,
    ) -> None:
        super().__init__(policy)
        self.scenario = scenario
        self.target_path = target_path
        self.shell_command = shell_command
        self.allowed_file_relpath = allowed_file_relpath
        self.allowed_content = allowed_content
        self.abort_wait_seconds = abort_wait_seconds
        self.commit_message = commit_message
        self.credits_per_turn = credits_per_turn
        self.quota_mode = quota_mode
        self.on_commit_callback = on_commit_callback

        self.start_count = 0
        self.abort_count = 0
        self.committed_sha: str | None = None
        self._abort_event = asyncio.Event()
        self._disconnected = False

    async def start(self, assignment: WorkerAssignment) -> None:
        self.start_count += 1
        self._assignment = assignment
        self._started_at_mono = time.monotonic()
        self._abort_event.clear()
        self._disconnected = False
        self._usage = UsageMetrics(model=assignment.model or "mock-copilot")

    def _commit_allowed_file(self, assignment: WorkerAssignment) -> str:
        resolved = self._policy.enforce_write(self.allowed_file_relpath)
        resolved.parent.mkdir(parents=True, exist_ok=True)
        resolved.write_text(self.allowed_content, encoding="utf-8")

        subprocess.run(
            ["git", "add", "--all"],
            cwd=assignment.worktree_path,
            check=True,
            capture_output=True,
            text=True,
            stdin=subprocess.DEVNULL,
        )
        msg = f"{self.commit_message}\n\nThread-Assignment-Id: {assignment.assignment_id}"
        subprocess.run(
            ["git", "commit", "-m", msg],
            cwd=assignment.worktree_path,
            check=True,
            capture_output=True,
            text=True,
            stdin=subprocess.DEVNULL,
        )
        sha_proc = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=assignment.worktree_path,
            check=True,
            capture_output=True,
            text=True,
            stdin=subprocess.DEVNULL,
        )
        sha = sha_proc.stdout.strip()
        self.committed_sha = sha
        if self.on_commit_callback is not None:
            self.on_commit_callback(sha)
        return sha

    async def stream_events(self) -> AsyncIterator[WorkerEvent]:
        if self._assignment is None:
            raise WorkerExecutionError("MockWorkerAdapter.stream_events called before start()")

        assignment = self._assignment
        yield self._redact_event(
            "session_start",
            f"Started mock session for {assignment.ticket_id}",
            {"assignment_id": assignment.assignment_id, "scenario": self.scenario},
        )

        if self.scenario == "out_of_scope_write":
            # Must raise BEFORE any disk side effect
            self._policy.enforce_write(self.target_path)
            return

        if self.scenario == "disallowed_shell":
            # Must raise BEFORE any subprocess execution
            self._policy.enforce_shell(self.shell_command)
            return

        if self.scenario == "quota_exceeded":
            if self.quota_mode == "provider":
                yield self._redact_event(
                    "paused_quota",
                    "Provider returned 429 rate limit / quota exhausted",
                    {"limit_type": "provider_quota"},
                )
                raise PausedQuota(
                    "Provider quota exhausted (429)",
                    limit_type="provider_quota",
                    credits_used=self._usage.credits_used,
                    turns_used=self._usage.turns_used,
                )
            if self.quota_mode == "credits":
                self._usage.turns_used += 1
                self._usage.credits_used = float(assignment.max_credits)
            else:
                self._usage.turns_used = assignment.max_turns
                self._usage.credits_used += self.credits_per_turn * assignment.max_turns
            yield self._redact_event(
                "paused_quota",
                "Quota cap reached during mock execution",
                {
                    "turns_used": self._usage.turns_used,
                    "credits_used": self._usage.credits_used,
                },
            )
            self._check_caps(assignment, self._usage)
            return

        if self.scenario == "slow_for_abort":
            try:
                await asyncio.wait_for(self._abort_event.wait(), timeout=self.abort_wait_seconds)
            except TimeoutError:
                pass
            if self._abort_event.is_set():
                yield self._redact_event("aborted", "Mock worker aborted")
            else:
                yield self._redact_event("session_idle", "Mock slow worker finished without abort")
            return

        if self.scenario == "secret_leak":
            self._usage.turns_used += 1
            self._usage.credits_used += self.credits_per_turn
            yield self._redact_event(
                "stdout",
                "Token ghp_secret1234567890abcdef and Authorization: Bearer tok_supersecret_xyz",
                {"env_line": "DB_PASSWORD=my_db_secret_pass"},
            )
            yield self._redact_event(
                "assistant_message",
                "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----",
            )
            yield self._redact_event("session_idle", "Completed secret leak simulation")
            return

        if self.scenario == "readonly_review":
            if not self._policy.readonly:
                raise WorkerExecutionError("Mock reviewer requires a read-only role")
            self._usage.turns_used += 1
            self._usage.credits_used += self.credits_per_turn
            self._check_caps(assignment, self._usage)
            yield self._redact_event("assistant_message", '{"findings":[]}')
            yield self._redact_event("session_idle", "Completed mock review protocol")
            return

        if self.scenario in ("commit_success", "crash_after_commit"):
            self._usage.turns_used += 1
            self._usage.credits_used += self.credits_per_turn
            self._usage.input_tokens += 120
            self._usage.output_tokens += 45
            sha = self._commit_allowed_file(assignment)
            yield self._redact_event(
                "usage",
                "Usage recorded",
                {
                    "turns_used": self._usage.turns_used,
                    "credits_used": self._usage.credits_used,
                },
            )
            yield self._redact_event(
                "commit",
                f"Committed {sha}",
                {"result_sha": sha, "trailer": f"Thread-Assignment-Id: {assignment.assignment_id}"},
            )
            if self.scenario == "crash_after_commit":
                raise WorkerExecutionError("Simulated process crash after commit before DB save")
            yield self._redact_event("session_idle", "Completed cleanly")
            return

    async def abort(self) -> None:
        self.abort_count += 1
        self._usage.aborted = True
        self._abort_event.set()
        if self._started_at_mono is not None:
            self._usage.duration_ms = (time.monotonic() - self._started_at_mono) * 1000.0

    async def disconnect(self) -> None:
        self._disconnected = True
        if self._started_at_mono is not None:
            self._usage.duration_ms = (time.monotonic() - self._started_at_mono) * 1000.0
