"""Integration tests for Git worktree + SQLite WAL crash recovery and merge guards."""

from __future__ import annotations

import asyncio
import subprocess
from pathlib import Path

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

    # Verify DB assignment was still `running` with `result_sha=None` when crash occurred
    pre_restart_asgn = state_repo.get_assignment("asgn-1")
    assert pre_restart_asgn is not None
    assert pre_restart_asgn.status == "running"
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
