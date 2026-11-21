"""Integration tests for Git worktree + SQLite WAL crash recovery and merge guards."""

from __future__ import annotations

import asyncio
import subprocess
from pathlib import Path
from typing import Any

import pytest

from thread_sdlc.config import PolicyConfig, ScopeConfig
from thread_sdlc.state import StateDatabase, StateRepository, ThreadRecord, TicketRecord
from thread_sdlc.workers import (
    MockWorkerAdapter,
    RolePolicy,
    WorkerExecutionError,
    WorkerManager,
    WorktreeManager,
)


def _git(args: list[str], cwd: Path) -> str:
    proc = subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
    )
    return proc.stdout.strip()


def _setup_repo(tmp_path: Path) -> tuple[Path, str]:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(["init", "-b", "main"], repo)
    _git(["config", "user.email", "dev@thread.local"], repo)
    _git(["config", "user.name", "Thread Dev"], repo)
    (repo / "README.md").write_text("# Inventory\n", encoding="utf-8")
    _git(["add", "README.md"], repo)
    _git(["commit", "-m", "Initial commit"], repo)
    base_sha = _git(["rev-parse", "HEAD"], repo)
    return repo, base_sha


def test_crash_after_commit_reconciles_without_reinvoking_worker(tmp_path: Path) -> None:
    repo, base_sha = _setup_repo(tmp_path)
    db = StateDatabase(repo_root=repo)
    state_repo = StateRepository(db)

    state_repo.create_thread(
        ThreadRecord(id="thr-1", title="Inventory Fix", track=3, base_sha=base_sha)
    )
    state_repo.create_ticket(
        TicketRecord(
            id="T1",
            thread_id="thr-1",
            title="Implement feature",
            role="backend",
            paths=["app/**"],
        )
    )

    crash_adapters: list[MockWorkerAdapter] = []

    def _crash_factory(pol: RolePolicy) -> MockWorkerAdapter:
        ad = MockWorkerAdapter(
            pol,
            scenario="crash_after_commit",
            allowed_file_relpath="app/feature.py",
            allowed_content="VALUE = 42\n",
        )
        crash_adapters.append(ad)
        return ad

    mgr1 = WorkerManager(
        repo_root=repo,
        db=db,
        policy=PolicyConfig(),
        scope=ScopeConfig(),
        adapter_factory=_crash_factory,
    )

    with pytest.raises(WorkerExecutionError, match="Simulated process crash after commit"):
        asyncio.run(mgr1.dispatch_ticket("thr-1", "T1", "Implement feature", assignment_id="asgn-1"))

    committed_sha = crash_adapters[0].committed_sha
    assert committed_sha is not None
    assert len(committed_sha) == 40

    # Verify handled WorkerExecutionError transitions assignment to `failed` with `result_sha=None`
    pre_restart_asgn = state_repo.get_assignment("asgn-1")
    assert pre_restart_asgn is not None
    assert pre_restart_asgn.status == "failed"
    assert pre_restart_asgn.result_sha is None

    # Simulated restart: brand new StateDatabase, WorktreeManager, and WorkerManager
    db2 = StateDatabase(repo_root=repo)
    wt2 = WorktreeManager(repo)
    restart_adapters: list[MockWorkerAdapter] = []

    def _restart_factory(pol: RolePolicy) -> MockWorkerAdapter:
        ad = MockWorkerAdapter(pol, scenario="commit_success")
        restart_adapters.append(ad)
        return ad

    mgr2 = WorkerManager(
        repo_root=repo,
        db=db2,
        policy=PolicyConfig(),
        scope=ScopeConfig(),
        adapter_factory=_restart_factory,
        worktree_manager=wt2,
    )

    dispatch_res = asyncio.run(
        mgr2.dispatch_ticket("thr-1", "T1", "Implement feature", assignment_id="asgn-1")
    )
    assert dispatch_res.reconciled is True
    assert dispatch_res.status == "reconciled_completed"
    assert dispatch_res.result_sha == committed_sha
    assert dispatch_res.worker_invoked is False
    assert len(restart_adapters) == 0  # Zero duplicate worker invocation!

    state_repo2 = StateRepository(db2)
    asgn_after = state_repo2.get_assignment("asgn-1")
    ticket_after = state_repo2.get_ticket("T1")
    assert asgn_after is not None and asgn_after.status == "reconciled_completed"
    assert asgn_after.result_sha == committed_sha
    assert ticket_after is not None and ticket_after.status == "done"
    assert ticket_after.result_sha == committed_sha

    events = mgr2.events.list_events("thr-1")
    assert any(
        e.type == "assignment_reconciled" and committed_sha in e.payload_json for e in events
    )


def test_reconcile_is_idempotent_across_repeated_calls(tmp_path: Path) -> None:
    repo, base_sha = _setup_repo(tmp_path)
    db = StateDatabase(repo_root=repo)
    sr = StateRepository(db)
    sr.create_thread(ThreadRecord(id="thr-idem", title="Idem", base_sha=base_sha))
    sr.create_ticket(TicketRecord(id="T1", thread_id="thr-idem", title="T1", role="backend"))

    mgr = WorkerManager(
        repo_root=repo,
        db=db,
        policy=PolicyConfig(),
        scope=ScopeConfig(),
        adapter_factory=lambda pol: MockWorkerAdapter(pol, scenario="crash_after_commit"),
    )
    with pytest.raises(WorkerExecutionError):
        asyncio.run(mgr.dispatch_ticket("thr-idem", "T1", "work", assignment_id="asgn-idem"))

    adapters: list[MockWorkerAdapter] = []

    def _no_call_factory(pol: RolePolicy) -> MockWorkerAdapter:
        ad = MockWorkerAdapter(pol)
        adapters.append(ad)
        return ad

    mgr2 = WorkerManager(
        repo_root=repo,
        db=StateDatabase(repo_root=repo),
        policy=PolicyConfig(),
        scope=ScopeConfig(),
        adapter_factory=_no_call_factory,
    )
    r1 = mgr2.reconcile_assignment("asgn-idem")
    r2 = mgr2.reconcile_assignment("asgn-idem")
    assert r1.reconciled is True
    assert r2.reconciled is True
    assert r1.result_sha == r2.result_sha
    assert r2.status == "reconciled_completed"
    assert len(adapters) == 0


def test_crash_before_commit_with_dirty_worktree_invokes_worker_on_resume(tmp_path: Path) -> None:
    repo, base_sha = _setup_repo(tmp_path)
    db = StateDatabase(repo_root=repo)
    sr = StateRepository(db)
    sr.create_thread(ThreadRecord(id="thr-dirty", title="Dirty", base_sha=base_sha))
    sr.create_ticket(TicketRecord(id="T1", thread_id="thr-dirty", title="T1", role="backend"))

    wt_mgr = WorktreeManager(repo)
    wt_info = wt_mgr.ensure_worktree("thr-dirty", "T1", base_ref=base_sha)
    # Simulate dirty partial edit left behind before commit
    (wt_info.path / "app").mkdir(parents=True, exist_ok=True)
    (wt_info.path / "app" / "partial.py").write_text("# uncommitted", encoding="utf-8")

    rec = wt_mgr.reconcile_assignment("thr-dirty", "T1", "asgn-dirty", base_sha=base_sha)
    assert rec.reconciled is False
    assert rec.has_uncommitted_changes is True

    resumed_adapters: list[MockWorkerAdapter] = []

    def _resume_factory(pol: RolePolicy) -> MockWorkerAdapter:
        ad = MockWorkerAdapter(pol, scenario="commit_success", allowed_file_relpath="app/final.py")
        resumed_adapters.append(ad)
        return ad

    mgr = WorkerManager(
        repo_root=repo,
        db=db,
        policy=PolicyConfig(),
        scope=ScopeConfig(),
        adapter_factory=_resume_factory,
        worktree_manager=wt_mgr,
    )
    res = asyncio.run(mgr.dispatch_ticket("thr-dirty", "T1", "finish work"))
    assert res.reconciled is False
    assert res.worker_invoked is True
    assert res.status == "completed"
    assert res.result_sha is not None
    assert len(resumed_adapters) == 1
    assert resumed_adapters[0].start_count == 1
    assert (wt_info.path / "app" / "partial.py").exists()


def test_worker_cannot_merge_into_base_branch(tmp_path: Path) -> None:
    repo, base_sha = _setup_repo(tmp_path)
    db = StateDatabase(repo_root=repo)
    sr = StateRepository(db)
    sr.create_thread(ThreadRecord(id="thr-m", title="Merge guard", base_sha=base_sha))
    sr.create_ticket(TicketRecord(id="T1", thread_id="thr-m", title="T1", role="backend"))

    mgr = WorkerManager(
        repo_root=repo,
        db=db,
        policy=PolicyConfig(),
        scope=ScopeConfig(),
        adapter_factory=lambda pol: MockWorkerAdapter(pol, scenario="commit_success"),
    )
    res = asyncio.run(mgr.dispatch_ticket("thr-m", "T1", "commit in worktree"))
    assert res.result_sha is not None

    # Base branch `main` must remain at base_sha
    assert _git(["rev-parse", "main"], repo) == base_sha

    wt_mgr = WorktreeManager(repo)
    with pytest.raises(PermissionError, match="human authorization"):
        wt_mgr.merge_worktree_human_only("thr-m", "T1", "main", human_authorized=False)

    merged_sha = wt_mgr.merge_worktree_human_only("thr-m", "T1", "main", human_authorized=True)
    assert _git(["rev-parse", "main"], repo) == merged_sha
    assert merged_sha != base_sha


def test_sigkill_running_assignment_reconciles_even_with_new_assignment_id(tmp_path: Path) -> None:
    """Hard process kill leaving `status='running'` reconciles prior commit even if new assignment_id is passed."""
    repo, base_sha = _setup_repo(tmp_path)
    db = StateDatabase(repo_root=repo)
    sr = StateRepository(db)
    sr.create_thread(ThreadRecord(id="thr-kill", title="SIGKILL", base_sha=base_sha))
    sr.create_ticket(TicketRecord(id="T1", thread_id="thr-kill", title="T1", role="backend"))

    wt_mgr = WorktreeManager(repo)
    wt_info = wt_mgr.ensure_worktree("thr-kill", "T1", base_ref=base_sha)
    (wt_info.path / "app").mkdir(parents=True, exist_ok=True)
    (wt_info.path / "app" / "work.py").write_text("OK = True\n", encoding="utf-8")
    committed_sha = wt_mgr.commit_worktree(wt_info.path, "Committed before SIGKILL", "asgn-old")

    from thread_sdlc.state import AssignmentRecord

    sr.create_assignment(
        AssignmentRecord(
            id="asgn-old",
            ticket_id="T1",
            adapter_type="MockWorkerAdapter",
            status="running",
            base_sha=base_sha,
            commit_trailer="Thread-Assignment-Id: asgn-old",
        )
    )

    restarted_adapters: list[MockWorkerAdapter] = []
    mgr = WorkerManager(
        repo_root=repo,
        db=StateDatabase(repo_root=repo),
        policy=PolicyConfig(),
        scope=ScopeConfig(),
        adapter_factory=lambda pol: (restarted_adapters.append(MockWorkerAdapter(pol)) or restarted_adapters[-1]),
    )
    res = asyncio.run(mgr.dispatch_ticket("thr-kill", "T1", "resume", assignment_id="asgn-new"))
    assert res.reconciled is True
    assert res.status == "reconciled_completed"
    assert res.result_sha == committed_sha
    assert res.worker_invoked is False
    assert len(restarted_adapters) == 0
    assert sr.get_assignment("asgn-old").status == "reconciled_completed"


def test_pre_commit_failure_marks_failed_allows_retry_and_enforces_retry_limit(
    tmp_path: Path,
) -> None:
    """Pre-commit exceptions mark assignment/ticket failed, emit assignment_failed, allow retry, and enforce max_retries_per_ticket."""
    from thread_sdlc.workers import ScopeViolationError, WorkerRetryLimitError

    repo, base_sha = _setup_repo(tmp_path)
    db = StateDatabase(repo_root=repo)
    sr = StateRepository(db)
    sr.create_thread(ThreadRecord(id="thr-fail", title="Retry", base_sha=base_sha))
    sr.create_ticket(TicketRecord(id="T-F1", thread_id="thr-fail", title="F1", role="backend"))
    sr.create_ticket(TicketRecord(id="T-F2", thread_id="thr-fail", title="F2", role="backend"))

    policy = PolicyConfig()
    policy.caps.max_workers_per_thread = 1
    policy.caps.max_retries_per_ticket = 1

    mgr_bad = WorkerManager(
        repo_root=repo,
        db=db,
        policy=policy,
        scope=ScopeConfig(),
        adapter_factory=lambda pol: MockWorkerAdapter(pol, scenario="out_of_scope_write"),
    )

    with pytest.raises(ScopeViolationError):
        asyncio.run(mgr_bad.dispatch_ticket("thr-fail", "T-F1", "attempt 1"))

    failed_asgn = sr.get_latest_assignment_for_ticket("T-F1")
    assert failed_asgn is not None
    assert failed_asgn.status == "failed"
    assert failed_asgn.ended_at is not None
    assert sr.get_ticket("T-F1").status == "failed"
    assert sr.count_active_assignments("thr-fail") == 0
    assert any(e.type == "assignment_failed" for e in mgr_bad.events.list_events("thr-fail"))

    # Another ticket on the same thread is NOT wedged by WorkerConcurrencyError
    mgr_good = WorkerManager(
        repo_root=repo,
        db=db,
        policy=policy,
        scope=ScopeConfig(),
        adapter_factory=lambda pol: MockWorkerAdapter(pol, scenario="commit_success"),
    )
    ok_res = asyncio.run(mgr_good.dispatch_ticket("thr-fail", "T-F2", "other ticket"))
    assert ok_res.status == "completed"

    # Retrying T-F1 succeeds while within retry budget (1 failed < max_retries=1? wait: 1 <= 1 allowed)
    res_retry = asyncio.run(mgr_good.dispatch_ticket("thr-fail", "T-F1", "retry valid"))
    assert res_retry.status == "completed"

    # Exhausting max_retries_per_ticket=1 (2 failures > 1) raises WorkerRetryLimitError
    sr.create_ticket(TicketRecord(id="T-F3", thread_id="thr-fail", title="F3", role="backend"))
    for _ in range(2):
        with pytest.raises(ScopeViolationError):
            asyncio.run(mgr_bad.dispatch_ticket("thr-fail", "T-F3", "bad attempt"))

    with pytest.raises(WorkerRetryLimitError):
        asyncio.run(mgr_bad.dispatch_ticket("thr-fail", "T-F3", "exceeded retries"))


def test_cancelled_dispatch_releases_concurrency_slot_and_allows_subsequent_ticket(
    tmp_path: Path,
) -> None:
    """Cancelling dispatch_ticket mid-stream aborts adapter, marks failed, and releases slot."""
    repo, base_sha = _setup_repo(tmp_path)
    db = StateDatabase(repo_root=repo)
    sr = StateRepository(db)
    sr.create_thread(ThreadRecord(id="thr-cancel", title="Cancel", base_sha=base_sha))
    sr.create_ticket(TicketRecord(id="T-C1", thread_id="thr-cancel", title="C1", role="backend"))
    sr.create_ticket(TicketRecord(id="T-C2", thread_id="thr-cancel", title="C2", role="backend"))

    policy = PolicyConfig()
    policy.caps.max_workers_per_thread = 1
    created_slow: list[MockWorkerAdapter] = []

    def _slow_factory(pol: RolePolicy) -> MockWorkerAdapter:
        ad = MockWorkerAdapter(pol, scenario="slow_for_abort", abort_wait_seconds=30.0)
        created_slow.append(ad)
        return ad

    mgr_slow = WorkerManager(
        repo_root=repo,
        db=db,
        policy=policy,
        scope=ScopeConfig(),
        adapter_factory=_slow_factory,
    )

    async def _run_and_cancel() -> None:
        task = asyncio.create_task(
            mgr_slow.dispatch_ticket("thr-cancel", "T-C1", "long run", assignment_id="asgn-cancel")
        )
        while not created_slow or created_slow[0].start_count == 0:
            await asyncio.sleep(0.01)
        await asyncio.sleep(0.02)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(_run_and_cancel())

    assert len(created_slow) == 1
    assert created_slow[0].abort_count == 1
    asgn = sr.get_assignment("asgn-cancel")
    assert asgn is not None
    assert asgn.status == "failed"
    assert asgn.ended_at is not None
    assert sr.get_ticket("T-C1").status == "failed"
    assert sr.count_active_assignments("thr-cancel") == 0
    assert any(e.type == "assignment_failed" for e in mgr_slow.events.list_events("thr-cancel"))

    # Subsequent ticket on the same thread succeeds without WorkerConcurrencyError
    mgr_ok = WorkerManager(
        repo_root=repo,
        db=db,
        policy=policy,
        scope=ScopeConfig(),
        adapter_factory=lambda pol: MockWorkerAdapter(pol, scenario="commit_success"),
    )
    ok_res = asyncio.run(mgr_ok.dispatch_ticket("thr-cancel", "T-C2", "next ticket"))
    assert ok_res.status == "completed"
    assert ok_res.result_sha is not None


def test_external_abort_marks_failed_instead_of_completed(tmp_path: Path) -> None:
    """External adapter.abort() mid-stream must mark failed and raise WorkerExecutionError, never done."""
    repo, base_sha = _setup_repo(tmp_path)
    db = StateDatabase(repo_root=repo)
    sr = StateRepository(db)
    sr.create_thread(ThreadRecord(id="thr-ext-abort", title="Ext Abort", base_sha=base_sha))
    sr.create_ticket(
        TicketRecord(id="T-A1", thread_id="thr-ext-abort", title="A1", role="backend")
    )

    created: list[MockWorkerAdapter] = []

    def _slow_factory(pol: RolePolicy) -> MockWorkerAdapter:
        ad = MockWorkerAdapter(pol, scenario="slow_for_abort", abort_wait_seconds=30.0)
        created.append(ad)
        return ad

    mgr = WorkerManager(
        repo_root=repo,
        db=db,
        policy=PolicyConfig(),
        scope=ScopeConfig(),
        adapter_factory=_slow_factory,
    )

    async def _run_and_abort() -> None:
        task = asyncio.create_task(
            mgr.dispatch_ticket(
                "thr-ext-abort", "T-A1", "wait", assignment_id="asgn-ext-abort"
            )
        )
        while not created or created[0].start_count == 0:
            await asyncio.sleep(0.01)
        await asyncio.sleep(0.02)
        await created[0].abort()
        with pytest.raises(WorkerExecutionError, match="aborted before completion"):
            await task

    asyncio.run(_run_and_abort())

    asgn = sr.get_assignment("asgn-ext-abort")
    assert asgn is not None
    assert asgn.status == "failed"
    assert asgn.result_sha is None
    assert asgn.ended_at is not None
    assert sr.get_ticket("T-A1").status == "failed"
    assert sr.count_active_assignments("thr-ext-abort") == 0
    events = mgr.events.list_events("thr-ext-abort")
    assert any(e.type == "assignment_failed" for e in events)
    assert not any(e.type == "assignment_completed" for e in events)


def test_concurrent_dispatch_ticket_enforces_max_workers_atomically_and_cleans_up_setup_failure(
    tmp_path: Path,
) -> None:
    """Two OS threads synchronized on a barrier cannot both bypass max_workers_per_thread=1, and setup failure frees the slot."""
    import threading

    from thread_sdlc.workers import WorkerConcurrencyError, WorktreeError

    repo, base_sha = _setup_repo(tmp_path)
    db = StateDatabase(repo_root=repo)
    sr = StateRepository(db)
    sr.create_thread(ThreadRecord(id="thr-mt", title="Concurrent", base_sha=base_sha))
    sr.create_ticket(TicketRecord(id="TM1", thread_id="thr-mt", title="TM1", role="backend"))
    sr.create_ticket(TicketRecord(id="TM2", thread_id="thr-mt", title="TM2", role="backend"))

    policy = PolicyConfig()
    policy.caps.max_workers_per_thread = 1

    started_lock = threading.Lock()
    started_count = 0

    class _SlowSuccessAdapter(MockWorkerAdapter):
        async def start(self, assignment: Any) -> None:
            nonlocal started_count
            with started_lock:
                started_count += 1
            await asyncio.sleep(0.15)
            await super().start(assignment)

    mgr = WorkerManager(
        repo_root=repo,
        db=db,
        policy=policy,
        scope=ScopeConfig(),
        adapter_factory=lambda pol: _SlowSuccessAdapter(pol, scenario="commit_success"),
    )

    barrier = threading.Barrier(2)
    results: list[tuple[str, Any]] = []
    res_lock = threading.Lock()

    def _run_dispatch(ticket_id: str) -> None:
        barrier.wait(timeout=5.0)
        try:
            res = asyncio.run(mgr.dispatch_ticket("thr-mt", ticket_id, "work"))
            with res_lock:
                results.append(("ok", res))
        except Exception as exc:
            with res_lock:
                results.append(("err", exc))

    t1 = threading.Thread(target=_run_dispatch, args=("TM1",))
    t2 = threading.Thread(target=_run_dispatch, args=("TM2",))
    t1.start()
    t2.start()
    t1.join(timeout=15.0)
    t2.join(timeout=15.0)

    assert len(results) == 2
    ok_items = [item for kind, item in results if kind == "ok"]
    err_items = [item for kind, item in results if kind == "err"]
    assert len(ok_items) == 1, f"Expected exactly 1 completed dispatch, got {results!r}"
    assert len(err_items) == 1 and isinstance(err_items[0], WorkerConcurrencyError), (
        f"Expected exactly 1 WorkerConcurrencyError, got {results!r}"
    )
    assert ok_items[0].status == "completed"
    assert started_count == 1
    assert sr.count_active_assignments("thr-mt") == 0

    # Verify ensure_worktree setup failure marks reservation failed and does NOT wedge future dispatches
    sr.create_ticket(TicketRecord(id="TM3", thread_id="thr-mt", title="TM3", role="backend"))
    sr.create_ticket(TicketRecord(id="TM4", thread_id="thr-mt", title="TM4", role="backend"))

    # Create a non-worktree directory at `.thread-state/worktrees/TM3` to trigger WorktreeError
    conflict_dir = repo / ".thread-state" / "worktrees" / "TM3"
    conflict_dir.mkdir(parents=True, exist_ok=True)
    (conflict_dir / "blocker.txt").write_text("block", encoding="utf-8")

    with pytest.raises(WorktreeError):
        asyncio.run(mgr.dispatch_ticket("thr-mt", "TM3", "should fail setup", assignment_id="asgn-tm3-fail"))

    failed_tm3 = sr.get_assignment("asgn-tm3-fail")
    assert failed_tm3 is not None
    assert failed_tm3.status == "failed"
    assert failed_tm3.ended_at is not None
    assert sr.get_ticket("TM3").status == "failed"
    assert sr.count_active_assignments("thr-mt") == 0
    assert any(
        e.type == "assignment_failed" and "asgn-tm3-fail" in e.payload_json
        for e in mgr.events.list_events("thr-mt")
    )

    # TM4 must dispatch cleanly without WorkerConcurrencyError
    res_tm4 = asyncio.run(mgr.dispatch_ticket("thr-mt", "TM4", "succeed after setup fail"))
    assert res_tm4.status == "completed"
