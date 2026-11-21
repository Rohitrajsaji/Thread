"""Worker adapters, RolePolicy permissions, isolated Git worktrees, and WorkerManager."""

from thread_sdlc.workers.adapter import (
    AdapterProbeResult,
    AdapterUnavailableError,
    BaseWorkerAdapter,
    MockWorkerAdapter,
    PausedQuota,
    UsageMetrics,
    WorkerAdapter,
    WorkerAssignment,
    WorkerEvent,
    WorkerExecutionError,
    is_quota_error,
)
from thread_sdlc.workers.copilot_cli import CopilotCliSubprocessAdapter, probe_cli
from thread_sdlc.workers.copilot_sdk import CopilotSdkAdapter, probe_sdk
from thread_sdlc.workers.manager import (
    DispatchResult,
    WorkerConcurrencyError,
    WorkerManager,
    WorkerRetryLimitError,
)
from thread_sdlc.workers.permissions import RolePolicy, ScopeViolationError, glob_match
from thread_sdlc.workers.worktree import (
    ReconcileResult,
    WorktreeError,
    WorktreeInfo,
    WorktreeManager,
    WorktreeStatus,
)

__all__ = [
    "AdapterProbeResult",
    "AdapterUnavailableError",
    "BaseWorkerAdapter",
    "CopilotCliSubprocessAdapter",
    "CopilotSdkAdapter",
    "DispatchResult",
    "MockWorkerAdapter",
    "PausedQuota",
    "ReconcileResult",
    "RolePolicy",
    "ScopeViolationError",
    "UsageMetrics",
    "WorkerAdapter",
    "WorkerAssignment",
    "WorkerConcurrencyError",
    "WorkerEvent",
    "WorkerExecutionError",
    "WorkerManager",
    "WorkerRetryLimitError",
    "WorktreeError",
    "WorktreeInfo",
    "WorktreeManager",
    "WorktreeStatus",
    "glob_match",
    "is_quota_error",
    "probe_cli",
    "probe_sdk",
]
