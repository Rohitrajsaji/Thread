"""Milestone M1 unit tests for config, redactor, SQLite WAL state, permissions, adapters, and CLI."""

from __future__ import annotations

import asyncio
import json
import os
import signal
import sqlite3
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest
import yaml
from typer.testing import CliRunner

from thread_sdlc.cli.main import app
from thread_sdlc.config import (
    PolicyConfig,
    RulesMap,
    ScopeConfig,
    ThreadConfig,
    build_initial_configs,
    detect_stack,
    load_from_git_ref,
    load_policy_from_git_ref,
    resolve_base_commit,
)
from thread_sdlc.governance import redactor
from thread_sdlc.state import EventLogger, StateDatabase, StateRepository, ThreadRecord, TicketRecord
from thread_sdlc.workers import (
    CopilotCliSubprocessAdapter,
    CopilotSdkAdapter,
    MockWorkerAdapter,
    PausedQuota,
    RolePolicy,
    ScopeViolationError,
    WorkerAssignment,
    WorkerConcurrencyError,
    WorkerManager,
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


def _init_git_repo(repo: Path) -> str:
    repo.mkdir(parents=True, exist_ok=True)
    _git(["init", "-b", "main"], repo)
    _git(["config", "user.email", "test@thread.local"], repo)
    _git(["config", "user.name", "Thread Test"], repo)
    (repo / "README.md").write_text("# Test Repo\n", encoding="utf-8")
    _git(["add", "README.md"], repo)
    _git(["commit", "-m", "Initial commit"], repo)
    return _git(["rev-parse", "HEAD"], repo)


# ---------------------------------------------------------------------------
# 1. Config, Stack Detector & Git Base-Ref Loader
# ---------------------------------------------------------------------------


def test_config_models_defaults_and_validation() -> None:
    cfg = ThreadConfig(project_name="demo")
    assert cfg.base_branch == "main"
    assert cfg.is_m3_enabled() is False

    pol = PolicyConfig()
    assert pol.tracks.track_1.max_files == 3
    assert pol.tracks.track_1.required_gates == []
    assert pol.tracks.track_2.required_gates == ["plan", "diff"]
    assert pol.tracks.track_3.required_gates == ["spec", "plan", "diff"]
    assert pol.caps.max_workers_per_thread == 1

    scope = ScopeConfig()
    assert set(scope.roles.keys()) >= {"backend", "frontend", "verifier", "reviewer_readonly"}
    assert scope.roles["reviewer_readonly"].readonly is True
    assert scope.roles["reviewer_readonly"].allowed_paths == []

    with pytest.raises(ValueError):
        ScopeConfig(roles={"reviewer_readonly": {"readonly": False, "allowed_paths": ["app/**"]}})

    rm = RulesMap.model_validate(
        {"rules": {"BR-INV-01": {"description": "Concurrency check", "test_nodeids": ["tests/a.py::t"]}}}
    )
    assert rm.rules["BR-INV-01"].rule_id == "BR-INV-01"


def test_stack_detector_detects_python_and_node(tmp_path: Path) -> None:
    repo = tmp_path / "fullstack"
    repo.mkdir()
    (repo / "pyproject.toml").write_text(
        '[build-system]\nrequires=["hatchling"]\n[project]\nname="inv-app"\ndependencies=["fastapi","pytest","ruff"]\n',
        encoding="utf-8",
    )
    (repo / "frontend").mkdir()
    (repo / "frontend" / "package.json").write_text(
        json.dumps(
            {
                "name": "inv-web",
                "dependencies": {"react": "^18.0.0"},
                "scripts": {"build": "vite build", "test": "vitest run"},
            }
        ),
        encoding="utf-8",
    )
    (repo / "app").mkdir()
    (repo / "tests").mkdir()

    detected = detect_stack(repo)
    assert detected.project_name == "inv-app"
    assert "python" in detected.languages
    assert "javascript" in detected.languages
    assert "fastapi" in detected.frameworks
    assert "react" in detected.frameworks
    assert detected.commands.test is not None and "pytest" in detected.commands.test
    assert detected.commands.lint == "ruff check ."

    bundle = build_initial_configs(detected)
    assert bundle.config.project_name == "inv-app"
    assert "reviewer_readonly" in bundle.scope.roles


def test_load_from_git_ref_reads_committed_policy_ignoring_dirty_wt(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _init_git_repo(repo)
    (repo / ".thread").mkdir()
    committed_policy = PolicyConfig()
    (repo / ".thread" / "policy.yaml").write_text(
        yaml.safe_dump(committed_policy.model_dump()), encoding="utf-8"
    )
    _git(["add", ".thread/policy.yaml"], repo)
    _git(["commit", "-m", "Add committed policy"], repo)
    base_sha = resolve_base_commit(repo, configured_base_branch="main")

    # Tamper with working tree copy without committing
    (repo / ".thread" / "policy.yaml").write_text(
        "base_branch: main\ncaps:\n  max_credits_per_thread: 999999\n  max_workers_per_thread: 50\n",
        encoding="utf-8",
    )

    raw = load_from_git_ref(repo, "main", ".thread/policy.yaml")
    assert "999999" not in raw
    loaded = load_policy_from_git_ref(repo, base_sha)
    assert loaded.caps.max_credits_per_thread == 500.0
    assert loaded.caps.max_workers_per_thread == 1


# ---------------------------------------------------------------------------
# 2. Pre-Storage Secret Redactor
# ---------------------------------------------------------------------------


def test_redactor_scrubs_all_required_patterns(tmp_path: Path) -> None:
    raw = "\n".join(
        [
            "gh_classic=ghp_1234567890abcdef123456",
            "gh_oauth=gho_abcdef1234567890",
            "gh_pat=github_pat_1234567890_abcdefghij",
            "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload123.sig456",
            "AWS_KEY=AKIAIOSFODNN7EXAMPLE",
            "aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "GCP_KEY=AIzaSyDummyKey1234567890abcdef",
            "DB_URL=postgres://admin:super_secret_pw@db.example.com:5432/prod",
            "DB_PASSWORD=my_env_secret_value",
            'API_SECRET="quoted_secret_val"',
            "normal_code = sum(range(10))",
        ]
    )
    scrubbed = redactor.redact_text(raw)
    for leaked in (
        "ghp_1234567890abcdef123456",
        "gho_abcdef1234567890",
        "github_pat_1234567890_abcdefghij",
        "eyJhbGciOiJIUzI1NiJ9.payload123.sig456",
        "AKIAIOSFODNN7EXAMPLE",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "AIzaSyDummyKey1234567890abcdef",
        "super_secret_pw",
        "my_env_secret_value",
        "quoted_secret_val",
    ):
        assert leaked not in scrubbed
    assert "normal_code = sum(range(10))" in scrubbed
    assert "DB_PASSWORD=[REDACTED]" in scrubbed

    # Streaming multi-line PEM block + RedactedLogWriter
    log_file = tmp_path / "worker.log"
    with redactor.RedactedLogWriter(log_file) as writer:
        writer.write_line("-----BEGIN RSA PRIVATE KEY-----")
        writer.write_line("MIIEowIBAAKCAQEAtotallysecretbase64line")
        writer.write_line("-----END RSA PRIVATE KEY-----")
        writer.write_line("After key safe line")

    content = log_file.read_text(encoding="utf-8")
    assert "MIIEowIBAAKCAQEAtotallysecretbase64line" not in content
    assert "[REDACTED]" in content
    assert "After key safe line" in content


# ---------------------------------------------------------------------------
# 3. SQLite WAL State & 7 Tables + Redacted Events
# ---------------------------------------------------------------------------


def test_sqlite_wal_schema_and_gitignore(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".gitignore").write_text("*.pyc\n.venv/\n", encoding="utf-8")

    db = StateDatabase(repo_root=repo)
    gitignore_lines = (repo / ".gitignore").read_text(encoding="utf-8").splitlines()
    assert "*.pyc" in gitignore_lines
    assert ".venv/" in gitignore_lines
    assert ".thread-state/" in gitignore_lines

    # Re-initializing does not duplicate `.thread-state/`
    StateDatabase(repo_root=repo)
    assert (repo / ".gitignore").read_text(encoding="utf-8").count(".thread-state/") == 1

    with sqlite3.connect(db.db_path) as conn:
        mode = conn.execute("PRAGMA journal_mode;").fetchone()[0]
        assert str(mode).lower() == "wal"
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';"
            ).fetchall()
        }
    assert tables == {
        "threads",
        "tickets",
        "assignments",
        "checkpoints",
        "annotations",
        "verification_runs",
        "events",
    }


def test_events_redacted_before_db_insert(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    db = StateDatabase(repo_root=repo)
    logger = EventLogger(db)

    secret_tok = "ghp_1234567890abcdef1234567890abcdef1234"
    bearer_tok = "Bearer supersecrettokenvalue12345"
    logger.emit(
        "thr-1",
        "worker.stdout",
        {"line": f"Found {secret_tok} and {bearer_tok}", "api_key": "raw_api_key_secret"},
    )

    with sqlite3.connect(db.db_path) as conn:
        raw_row = conn.execute("SELECT payload_json FROM events").fetchone()[0]
    assert secret_tok not in raw_row
    assert "supersecrettokenvalue12345" not in raw_row
    assert "raw_api_key_secret" not in raw_row
    assert "[REDACTED]" in raw_row


# ---------------------------------------------------------------------------
# 4. RolePolicy Traversal, Shell & reviewer_readonly Blocking
# ---------------------------------------------------------------------------


def test_role_policy_blocks_traversal_symlinks_and_absolute_paths(tmp_path: Path) -> None:
    wt = tmp_path / "worktree"
    wt.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("outside", encoding="utf-8")
    link = wt / "app" / "escape_link.py"
    link.parent.mkdir(parents=True)
    link.symlink_to(outside)

    policy = RolePolicy(
        role="backend",
        worktree_root=wt,
        allowed_paths=["app/**", "tests/**"],
        denied_paths=[".thread/policy.yaml"],
        deny_gate_files=["tests/acceptance/**"],
        allowed_shell_prefixes=["pytest", "git status"],
    )

    assert policy.enforce_write("app/service.py") == (wt / "app" / "service.py").resolve()

    for bad_target in (
        "../outside.txt",
        "app/../../outside.txt",
        str(tmp_path / "abs.py"),
        "app/escape_link.py",
        ".git/config",
        ".thread-state/thread.db",
        ".thread/policy.yaml",
        "tests/acceptance/test_gate.py",
        "frontend/App.tsx",
    ):
        with pytest.raises(ScopeViolationError):
            policy.enforce_write(bad_target)


def test_role_policy_shell_injection_and_boundary_checks(tmp_path: Path) -> None:
    wt = tmp_path / "wt"
    wt.mkdir()
    policy = RolePolicy(
        role="backend",
        worktree_root=wt,
        allowed_paths=["app/**"],
        allowed_shell_prefixes=["pytest", "git status", "git diff"],
    )

    assert policy.enforce_shell("pytest tests/unit/test_ok.py") == [
        "pytest",
        "tests/unit/test_ok.py",
    ]

    for bad_cmd in (
        "pytest && rm -rf /",
        "pytest; cat /etc/passwd",
        "pytest > ../out.txt",
        "pytest $(whoami)",
        "pytest_evil",
        "git merge feature",
        "git push origin main",
        "pytest ../outside.py",
    ):
        with pytest.raises(ScopeViolationError):
            policy.enforce_shell(bad_cmd)


def test_reviewer_readonly_rejects_all_writes_and_mutating_commands(tmp_path: Path) -> None:
    wt = tmp_path / "wt"
    wt.mkdir()
    scope = ScopeConfig()
    ro_policy = RolePolicy.from_scope_config("reviewer_readonly", scope, wt)

    with pytest.raises(ScopeViolationError):
        ro_policy.enforce_write("app/main.py")

    for bad_cmd in ("rm -f app/main.py", "git commit -m x", "touch foo", "sed -i s/a/b/ x"):
        with pytest.raises(ScopeViolationError):
            ro_policy.enforce_shell(bad_cmd)

    assert ro_policy.enforce_shell("git diff") == ["git", "diff"]


# ---------------------------------------------------------------------------
# 5. Pre-Write Blocking on SDK, CLI & Mock Adapters (Zero Disk Changes)
# ---------------------------------------------------------------------------


class _FakeSdkSession:
    def __init__(self, hooks: dict[str, Any], on_permission_request: Any, worktree: Path, script: str) -> None:
        self._hooks = hooks
        self._on_permission_request = on_permission_request
        self._worktree = worktree
        self._script = script
        self._handlers: list[Any] = []
        self._aborted = asyncio.Event()

    def on(self, cb: Any) -> None:
        self._handlers.append(cb)

    async def send(self, prompt: str) -> str:
        pre_hook = self._hooks["on_pre_tool_use"]
        if self._script == "out_of_scope":
            dec = await pre_hook(
                {"toolName": "write_file", "toolArgs": {"path": ".thread/policy.yaml"}}, {}
            )
            if dec.get("permissionDecision") == "allow":
                (self._worktree / ".thread").mkdir(parents=True, exist_ok=True)
                (self._worktree / ".thread" / "policy.yaml").write_text("pwned", encoding="utf-8")

            perm_res = await self._on_permission_request(
                {"kind": "write", "file_name": "../outside.txt"}, {}
            )
            if perm_res.get("kind") == "approved":
                (self._worktree.parent / "outside.txt").write_text("pwned", encoding="utf-8")
        elif self._script == "readonly_write":
            dec = await pre_hook({"toolName": "edit_file", "toolArgs": {"path": "app/main.py"}}, {})
            if dec.get("permissionDecision") == "allow":
                (self._worktree / "app").mkdir(parents=True, exist_ok=True)
                (self._worktree / "app" / "main.py").write_text("pwned", encoding="utf-8")
        elif self._script == "quota_hit":
            for h in self._handlers:
                h(
                    {
                        "type": "assistant.usage",
                        "data": {"input_tokens": 100, "output_tokens": 50, "cost": 25.0},
                    }
                )
        elif self._script == "slow":
            try:
                await asyncio.wait_for(self._aborted.wait(), timeout=10.0)
            except TimeoutError:
                pass
            return "aborted"

        for h in self._handlers:
            h({"type": "session.idle", "data": {}})
        return "done"

    async def abort(self) -> None:
        self._aborted.set()
        for h in self._handlers:
            h({"type": "abort", "data": {}})

    async def disconnect(self) -> None:
        return None


class _FakeSdkClient:
    def __init__(self, worktree: Path, script: str) -> None:
        self._worktree = worktree
        self._script = script

    async def start(self) -> None:
        return None

    async def stop(self) -> None:
        return None

    async def create_session(self, **kwargs: Any) -> _FakeSdkSession:
        return _FakeSdkSession(
            kwargs["hooks"],
            kwargs["on_permission_request"],
            self._worktree,
            self._script,
        )


def test_sdk_adapter_blocks_out_of_scope_write_before_disk_change(tmp_path: Path) -> None:
    wt = tmp_path / "wt"
    wt.mkdir()
    policy = RolePolicy(
        role="backend",
        worktree_root=wt,
        allowed_paths=["app/**"],
        denied_paths=[".thread/policy.yaml"],
    )
    adapter = CopilotSdkAdapter(policy, client_factory=lambda: _FakeSdkClient(wt, "out_of_scope"))
    asgn = WorkerAssignment(
        assignment_id="a-sdk-1",
        thread_id="t-1",
        ticket_id="T1",
        role="backend",
        instructions="edit policy",
        worktree_path=wt,
        base_sha="HEAD",
    )

    async def _run() -> None:
        await adapter.start(asgn)
        try:
            async for _ in adapter.stream_events():
                pass
        finally:
            await adapter.disconnect()

    with pytest.raises(ScopeViolationError):
        asyncio.run(_run())

    assert not (wt / ".thread" / "policy.yaml").exists()
    assert not (tmp_path / "outside.txt").exists()


def test_cli_adapter_blocks_out_of_scope_write_via_pre_tool_hook_before_disk_change(
    tmp_path: Path,
) -> None:
    wt = tmp_path / "wt"
    wt.mkdir()
    policy = RolePolicy(
        role="backend",
        worktree_root=wt,
        allowed_paths=["app/**"],
        denied_paths=[".thread/policy.yaml"],
    )

    # Real subprocess simulating Copilot CLI invoking preToolUse hook before touching disk
    cli_sim = "\n".join(
        [
            "import json, subprocess, sys",
            "from pathlib import Path",
            "req = json.dumps({'toolName': 'write_file', 'toolArgs': {'path': '../outside.txt'}})",
            "p = subprocess.run([sys.executable, '-m', 'thread_sdlc.workers.permissions'], input=req, text=True, capture_output=True)",
            "dec = json.loads(p.stdout)",
            "print(json.dumps(dec))",
            "if dec.get('permissionDecision') == 'allow':",
            "    Path('../outside.txt').write_text('pwned', encoding='utf-8')",
        ]
    )
    adapter = CopilotCliSubprocessAdapter(
        policy,
        command_builder=lambda _a, _cfg: [sys.executable, "-c", cli_sim],
    )
    asgn = WorkerAssignment(
        assignment_id="a-cli-1",
        thread_id="t-1",
        ticket_id="T1",
        role="backend",
        instructions="escape",
        worktree_path=wt,
        base_sha="HEAD",
    )

    async def _run() -> None:
        await adapter.start(asgn)
        try:
            async for _ in adapter.stream_events():
                pass
        finally:
            await adapter.disconnect()

    with pytest.raises(ScopeViolationError):
        asyncio.run(_run())

    assert not (tmp_path / "outside.txt").exists()


def test_sdk_and_cli_adapters_enforce_reviewer_readonly(tmp_path: Path) -> None:
    wt = tmp_path / "wt"
    wt.mkdir()
    ro_policy = RolePolicy.from_scope_config("reviewer_readonly", ScopeConfig(), wt)

    sdk_adapter = CopilotSdkAdapter(
        ro_policy, client_factory=lambda: _FakeSdkClient(wt, "readonly_write")
    )
    asgn = WorkerAssignment(
        assignment_id="a-ro-1",
        thread_id="t-1",
        ticket_id="T1",
        role="reviewer_readonly",
        instructions="modify app",
        worktree_path=wt,
        base_sha="HEAD",
    )

    async def _run_sdk() -> None:
        await sdk_adapter.start(asgn)
        try:
            async for _ in sdk_adapter.stream_events():
                pass
        finally:
            await sdk_adapter.disconnect()

    with pytest.raises(ScopeViolationError):
        asyncio.run(_run_sdk())
    assert not (wt / "app" / "main.py").exists()

    cli_sim = "\n".join(
        [
            "import json, subprocess, sys",
            "from pathlib import Path",
            "req = json.dumps({'toolName': 'edit_file', 'toolArgs': {'path': 'app/main.py'}})",
            "p = subprocess.run([sys.executable, '-m', 'thread_sdlc.workers.permissions'], input=req, text=True, capture_output=True)",
            "dec = json.loads(p.stdout)",
            "print(json.dumps(dec))",
            "if dec.get('permissionDecision') == 'allow':",
            "    Path('app').mkdir(exist_ok=True)",
            "    Path('app/main.py').write_text('pwned', encoding='utf-8')",
        ]
    )
    cli_adapter = CopilotCliSubprocessAdapter(
        ro_policy, command_builder=lambda _a, _cfg: [sys.executable, "-c", cli_sim]
    )

    async def _run_cli() -> None:
        await cli_adapter.start(asgn)
        try:
            async for _ in cli_adapter.stream_events():
                pass
        finally:
            await cli_adapter.disconnect()

    with pytest.raises(ScopeViolationError):
        asyncio.run(_run_cli())
    assert not (wt / "app" / "main.py").exists()


def test_mock_adapter_out_of_scope_and_secret_redaction(tmp_path: Path) -> None:
    wt = tmp_path / "wt"
    wt.mkdir()
    policy = RolePolicy(role="backend", worktree_root=wt, allowed_paths=["app/**"])

    bad_mock = MockWorkerAdapter(policy, scenario="out_of_scope_write", target_path=".thread/policy.yaml")
    asgn = WorkerAssignment(
        assignment_id="m1",
        thread_id="t1",
        ticket_id="T1",
        role="backend",
        instructions="bad",
        worktree_path=wt,
        base_sha="HEAD",
    )

    async def _run_bad() -> None:
        await bad_mock.start(asgn)
        async for _ in bad_mock.stream_events():
            pass

    with pytest.raises(ScopeViolationError):
        asyncio.run(_run_bad())
    assert not (wt / ".thread" / "policy.yaml").exists()

    leak_mock = MockWorkerAdapter(policy, scenario="secret_leak")

    async def _run_leak() -> list[Any]:
        await leak_mock.start(asgn)
        return [evt async for evt in leak_mock.stream_events()]

    events = asyncio.run(_run_leak())
    joined = "\n".join(e.message + " " + json.dumps(e.data) for e in events)
    assert "ghp_secret1234567890abcdef" not in joined
    assert "tok_supersecret_xyz" not in joined
    assert "my_db_secret_pass" not in joined
    assert "MIIEowIBAAKCAQEA" not in joined
    assert "[REDACTED]" in joined


# ---------------------------------------------------------------------------
# 6. PausedQuota Zero-Retry & <2s Abort
# ---------------------------------------------------------------------------


def test_paused_quota_zero_retry_across_adapters_and_manager(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    base_sha = _init_git_repo(repo)
    db = StateDatabase(repo_root=repo)
    state_repo = StateRepository(db)
    state_repo.create_thread(ThreadRecord(id="thr-q", title="Quota", base_sha=base_sha))
    state_repo.create_ticket(
        TicketRecord(id="T-Q", thread_id="thr-q", title="Quota ticket", role="backend")
    )

    created_adapters: list[MockWorkerAdapter] = []

    def _factory(pol: RolePolicy) -> MockWorkerAdapter:
        ad = MockWorkerAdapter(pol, scenario="quota_exceeded", quota_mode="credits")
        created_adapters.append(ad)
        return ad

    policy = PolicyConfig()
    policy.caps.max_credits_per_thread = 5.0
    mgr = WorkerManager(
        repo_root=repo,
        db=db,
        policy=policy,
        scope=ScopeConfig(),
        adapter_factory=_factory,
    )

    with pytest.raises(PausedQuota):
        asyncio.run(mgr.dispatch_ticket("thr-q", "T-Q", "run"))

    assert len(created_adapters) == 1
    assert created_adapters[0].start_count == 1
    assert state_repo.get_thread("thr-q").status == "PausedQuota"

    # Second dispatch while PausedQuota raises immediately without starting a worker
    with pytest.raises(PausedQuota):
        asyncio.run(mgr.dispatch_ticket("thr-q", "T-Q", "run again"))
    assert len(created_adapters) == 1

    # SDK adapter quota check
    sdk_wt = tmp_path / "sdk_wt"
    sdk_wt.mkdir()
    sdk_pol = RolePolicy(role="backend", worktree_root=sdk_wt, allowed_paths=["app/**"])
    sdk_ad = CopilotSdkAdapter(sdk_pol, client_factory=lambda: _FakeSdkClient(sdk_wt, "quota_hit"))
    sdk_asgn = WorkerAssignment(
        assignment_id="a-q-sdk",
        thread_id="thr-q",
        ticket_id="T-Q",
        role="backend",
        instructions="quota",
        worktree_path=sdk_wt,
        base_sha="HEAD",
        max_credits=10.0,
    )

    async def _run_sdk_quota() -> None:
        await sdk_ad.start(sdk_asgn)
        try:
            async for _ in sdk_ad.stream_events():
                pass
        finally:
            await sdk_ad.disconnect()

    with pytest.raises(PausedQuota):
        asyncio.run(_run_sdk_quota())
    assert sdk_ad.start_count == 1

    # CLI adapter quota check
    cli_ad = CopilotCliSubprocessAdapter(
        sdk_pol,
        command_builder=lambda _a, _cfg: [
            sys.executable,
            "-c",
            "print('Error 429: rate limit / quota exceeded')",
        ],
    )

    async def _run_cli_quota() -> None:
        await cli_ad.start(sdk_asgn)
        try:
            async for _ in cli_ad.stream_events():
                pass
        finally:
            await cli_ad.disconnect()

    with pytest.raises(PausedQuota):
        asyncio.run(_run_cli_quota())
    assert cli_ad.start_count == 1


def test_abort_completes_under_2s_without_orphan_process(tmp_path: Path) -> None:
    wt = tmp_path / "wt"
    wt.mkdir()
    pol = RolePolicy(role="backend", worktree_root=wt, allowed_paths=["app/**"])
    asgn = WorkerAssignment(
        assignment_id="a-abort",
        thread_id="t-1",
        ticket_id="T1",
        role="backend",
        instructions="wait",
        worktree_path=wt,
        base_sha="HEAD",
    )

    # 1. MockWorkerAdapter abort
    mock_ad = MockWorkerAdapter(pol, scenario="slow_for_abort", abort_wait_seconds=30.0)

    async def _abort_mock() -> float:
        await mock_ad.start(asgn)
        task = asyncio.create_task(mock_ad.stream_events().__anext__())
        await asyncio.sleep(0.02)
        t0 = time.perf_counter()
        await mock_ad.abort()
        elapsed = time.perf_counter() - t0
        await task
        await mock_ad.disconnect()
        return elapsed

    assert asyncio.run(_abort_mock()) < 2.0

    # 2. CopilotSdkAdapter abort
    sdk_ad = CopilotSdkAdapter(pol, client_factory=lambda: _FakeSdkClient(wt, "slow"))

    async def _abort_sdk() -> float:
        await sdk_ad.start(asgn)
        await asyncio.sleep(0.02)
        t0 = time.perf_counter()
        await sdk_ad.abort()
        elapsed = time.perf_counter() - t0
        await sdk_ad.disconnect()
        return elapsed

    assert asyncio.run(_abort_sdk()) < 2.0

    # 3. CopilotCliSubprocessAdapter real process-tree abort
    cli_ad = CopilotCliSubprocessAdapter(
        pol,
        command_builder=lambda _a, _cfg: [sys.executable, "-c", "import time; time.sleep(60)"],
    )

    async def _abort_cli() -> tuple[float, int]:
        await cli_ad.start(asgn)
        assert cli_ad._proc is not None
        pid = cli_ad._proc.pid
        await asyncio.sleep(0.05)
        t0 = time.perf_counter()
        await cli_ad.abort()
        elapsed = time.perf_counter() - t0
        await cli_ad.disconnect()
        return elapsed, pid

    elapsed, pid = asyncio.run(_abort_cli())
    assert elapsed < 2.0
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


# ---------------------------------------------------------------------------
# 7. Worker Concurrency Cap & `thread doctor --spike`
# ---------------------------------------------------------------------------


def test_worker_concurrency_cap_blocks_second_active_worker(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    base_sha = _init_git_repo(repo)
    db = StateDatabase(repo_root=repo)
    sr = StateRepository(db)
    sr.create_thread(ThreadRecord(id="thr-c", title="Cap", base_sha=base_sha))
    sr.create_ticket(TicketRecord(id="T1", thread_id="thr-c", title="T1", role="backend"))
    sr.create_ticket(TicketRecord(id="T2", thread_id="thr-c", title="T2", role="backend"))

    from thread_sdlc.state import AssignmentRecord

    sr.create_assignment(
        AssignmentRecord(
            id="asgn-active",
            ticket_id="T1",
            adapter_type="MockWorkerAdapter",
            status="running",
            base_sha=base_sha,
            commit_trailer="Thread-Assignment-Id: asgn-active",
        )
    )

    mgr = WorkerManager(
        repo_root=repo,
        db=db,
        policy=PolicyConfig(),  # max_workers_per_thread=1
        scope=ScopeConfig(),
        adapter_factory=lambda pol: MockWorkerAdapter(pol),
    )

    with pytest.raises(WorkerConcurrencyError):
        asyncio.run(mgr.dispatch_ticket("thr-c", "T2", "work"))


def test_doctor_spike_generates_report_and_handles_missing_cli(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _init_git_repo(repo)
    report_out = repo / ".thread-state" / "doctor-spike.md"
    runner = CliRunner()
    result = runner.invoke(
        app,
        ["doctor", "--spike", "--repo", str(repo), "--output", str(report_out)],
    )
    assert result.exit_code == 0, result.output
    assert "CopilotSdkAdapter" in result.output
    assert "CopilotCliSubprocessAdapter" in result.output
    assert "Pre-write scope block (SDK)" in result.output
    assert "Pre-write scope block (CLI)" in result.output
    assert "PausedQuota zero-retry simulation" in result.output
    assert report_out.is_file()


# ---------------------------------------------------------------------------
# 8. Iteration 2 Regression Tests (Security, SDK, CLI, Redactor, Hardening)
# ---------------------------------------------------------------------------


def test_sdk_send_and_wait_and_nonblocking_send_lifecycle(tmp_path: Path) -> None:
    """Verify send_and_wait() is preferred and non-blocking send() waits for session.idle."""
    wt = tmp_path / "wt"
    wt.mkdir()
    policy = RolePolicy(role="backend", worktree_root=wt, allowed_paths=["app/**"])
    asgn = WorkerAssignment(
        assignment_id="a-life",
        thread_id="t-1",
        ticket_id="T1",
        role="backend",
        instructions="hello",
        worktree_path=wt,
        base_sha="HEAD",
        timeout_seconds=12.0,
    )

    # 1. Non-blocking send() that returns immediately while events arrive asynchronously
    class _AsyncSendSession:
        def __init__(self) -> None:
            self._handlers: list[Any] = []
            self.send_called = False

        def on(self, cb: Any) -> None:
            self._handlers.append(cb)

        async def send(self, prompt: str) -> str:
            self.send_called = True

            async def _emit_later() -> None:
                await asyncio.sleep(0.03)
                for h in self._handlers:
                    h({"type": "assistant.message.delta", "data": {"delta_content": "-----BEGIN RSA PRIVATE KEY-----\n"}})
                    h({"type": "assistant.message.delta", "data": {"delta_content": "MIIEow_CHUNKED_SECRET_BODY\n"}})
                    h({"type": "assistant.message.delta", "data": {"delta_content": "-----END RSA PRIVATE KEY-----"}})
                    h({"type": "assistant.message.delta", "data": {"delta_content": "final-ok"}})
                    h({"type": "session.idle", "data": {}})

            asyncio.create_task(_emit_later())
            return "msg-id-123"

        async def abort(self) -> None:
            return None

        async def disconnect(self) -> None:
            return None

    class _AsyncClient:
        def __init__(self) -> None:
            self.session = _AsyncSendSession()
            self.session_kwargs: dict[str, Any] = {}

        async def create_session(self, **kwargs: Any) -> _AsyncSendSession:
            self.session_kwargs = kwargs
            return self.session

    client1 = _AsyncClient()
    ad1 = CopilotSdkAdapter(policy, client_factory=lambda: client1)

    async def _run_async_send() -> list[Any]:
        await ad1.start(asgn)
        try:
            return [e async for e in ad1.stream_events()]
        finally:
            await ad1.disconnect()

    evts = asyncio.run(_run_async_send())
    assert client1.session.send_called is True
    msgs = [e.message for e in evts if e.type == "assistant_message"]
    assert "final-ok" in msgs
    assert all("MIIEow_CHUNKED_SECRET_BODY" not in m for m in msgs)

    # 2. send_and_wait() is preferred when present and receives timeout
    class _SendAndWaitSession:
        def __init__(self) -> None:
            self._handlers: list[Any] = []
            self.seen_timeout: float | None = None

        def on(self, cb: Any) -> None:
            self._handlers.append(cb)

        async def send(self, prompt: str) -> str:
            raise AssertionError("send() should not be called when send_and_wait() exists")

        async def send_and_wait(self, prompt: str, *, timeout: float = 60.0) -> None:
            self.seen_timeout = timeout
            for h in self._handlers:
                h({"type": "assistant.message", "data": {"content": "waited-ok"}})
                h({"type": "session.idle", "data": {}})

        async def disconnect(self) -> None:
            return None

    saw_session = _SendAndWaitSession()

    class _SawClient:
        async def create_session(self, **kwargs: Any) -> _SendAndWaitSession:
            return saw_session

    ad2 = CopilotSdkAdapter(policy, client_factory=lambda: _SawClient())

    async def _run_saw() -> list[Any]:
        await ad2.start(asgn)
        try:
            return [e async for e in ad2.stream_events()]
        finally:
            await ad2.disconnect()

    evts2 = asyncio.run(_run_saw())
    assert saw_session.seen_timeout == 12.0
    assert any(e.type == "assistant_message" and e.message == "waited-ok" for e in evts2)


def test_sdk_permission_request_extracts_args_and_readonly_excluded_tools(tmp_path: Path) -> None:
    """Verify PermissionRequestCustomTool/Mcp .args inspection and full readonly excluded_tools."""
    from copilot.generated.session_events import PermissionRequestCustomTool, PermissionRequestMcp

    wt = tmp_path / "wt"
    wt.mkdir()
    be_policy = RolePolicy(role="backend", worktree_root=wt, allowed_paths=["app/**"])
    sdk = CopilotSdkAdapter(be_policy)

    for req in (
        PermissionRequestCustomTool(
            tool_description="read file",
            tool_name="read_file",
            args={"path": "/etc/passwd"},
        ),
        PermissionRequestMcp(
            read_only=True,
            server_name="fs",
            tool_name="read_file",
            tool_title="Read File",
            args={"path": "/etc/passwd"},
        ),
    ):
        decision = asyncio.run(sdk._on_permission_request(req))
        assert getattr(decision, "kind", None) == "denied-by-rules"

    # Readonly excluded_tools aligns with _WRITE_TOOLS
    ro_policy = RolePolicy.from_scope_config("reviewer_readonly", ScopeConfig(), wt)
    captured_kwargs: dict[str, Any] = {}

    class _CapSession:
        def on(self, cb: Any) -> None:
            self._cb = cb

        async def send_and_wait(self, prompt: str, *, timeout: float = 60.0) -> None:
            self._cb({"type": "session.idle", "data": {}})

        async def disconnect(self) -> None:
            return None

    class _CapClient:
        async def create_session(self, **kwargs: Any) -> _CapSession:
            captured_kwargs.update(kwargs)
            return _CapSession()

    ro_sdk = CopilotSdkAdapter(ro_policy, client_factory=lambda: _CapClient())
    asgn = WorkerAssignment(
        assignment_id="a-ro-ex",
        thread_id="t-1",
        ticket_id="T1",
        role="reviewer_readonly",
        instructions="review",
        worktree_path=wt,
        base_sha="HEAD",
    )

    async def _run() -> None:
        await ro_sdk.start(asgn)
        try:
            async for _ in ro_sdk.stream_events():
                pass
        finally:
            await ro_sdk.disconnect()

    asyncio.run(_run())
    excluded = set(captured_kwargs.get("excluded_tools", []))
    for expected_tool in ("delete", "unlink", "move", "rename", "fs_create", "file_save", "apply_patch"):
        assert expected_tool in excluded


def test_cli_adapter_scrubs_multiline_pem_and_quotes_hook_executable(tmp_path: Path) -> None:
    """Verify StreamRedactor per CLI pipe prevents multi-line PEM leakage in events, logs, and SQLite."""
    repo = tmp_path / "repo"
    base_sha = _init_git_repo(repo)
    db = StateDatabase(repo_root=repo)
    sr = StateRepository(db)
    sr.create_thread(ThreadRecord(id="thr-pem", title="PEM", base_sha=base_sha))
    sr.create_ticket(TicketRecord(id="T-PEM", thread_id="thr-pem", title="PEM", role="backend"))

    cli_script = "\n".join(
        [
            "print('-----BEGIN RSA PRIVATE KEY-----')",
            "print('MIIEowIBAAKCAQEA_LEAKED_PRIVATE_KEY_BODY_LINE_1')",
            "print('MIIEowIBAAKCAQEA_LEAKED_PRIVATE_KEY_BODY_LINE_2')",
            "print('-----END RSA PRIVATE KEY-----')",
            "print('safe-output-after-pem')",
        ]
    )
    mgr = WorkerManager(
        repo_root=repo,
        db=db,
        policy=PolicyConfig(),
        scope=ScopeConfig(),
        adapter_factory=lambda pol: CopilotCliSubprocessAdapter(
            pol,
            command_builder=lambda _a, _cfg: [sys.executable, "-c", cli_script],
        ),
    )
    res = asyncio.run(mgr.dispatch_ticket("thr-pem", "T-PEM", "run"))
    assert res.log_path is not None
    log_text = (repo / res.log_path).read_text(encoding="utf-8")
    assert "MIIEowIBAAKCAQEA_LEAKED_PRIVATE_KEY_BODY_LINE_1" not in log_text
    assert "MIIEowIBAAKCAQEA_LEAKED_PRIVATE_KEY_BODY_LINE_2" not in log_text
    assert "safe-output-after-pem" in log_text

    with sqlite3.connect(db.db_path) as conn:
        all_events = "\n".join(r[0] for r in conn.execute("SELECT payload_json FROM events").fetchall())
    assert "MIIEowIBAAKCAQEA_LEAKED_PRIVATE_KEY_BODY_LINE_1" not in all_events
    assert "MIIEowIBAAKCAQEA_LEAKED_PRIVATE_KEY_BODY_LINE_2" not in all_events

    # Verify guard.json quotes sys.executable and readonly denies full write-tool list
    ro_policy = RolePolicy.from_scope_config("reviewer_readonly", ScopeConfig(), tmp_path)
    ro_cli = CopilotCliSubprocessAdapter(ro_policy)
    asgn = WorkerAssignment(
        assignment_id="a-guard",
        thread_id="t",
        ticket_id="T",
        role="reviewer_readonly",
        instructions="review",
        worktree_path=tmp_path,
        base_sha="HEAD",
    )
    runtime_path, _, _ = ro_cli._prepare_runtime_files(asgn)
    try:
        guard = json.loads((runtime_path / "hooks" / "guard.json").read_text(encoding="utf-8"))
        import shlex

        expected_prefix = f"{shlex.quote(sys.executable)} -m thread_sdlc.workers.permissions"
        assert guard["hooks"]["preToolUse"][0]["bash"] == expected_prefix
    finally:
        if ro_cli._runtime_dir is not None:
            ro_cli._runtime_dir.cleanup()
            ro_cli._runtime_dir = None


def test_role_policy_iteration2_hardening(tmp_path: Path) -> None:
    """Verify mutating tools, Move to/rename to, --output, python -c, and macOS symlink prefixes."""
    wt = tmp_path / "wt"
    wt.mkdir()
    (wt / "app").mkdir()
    be = RolePolicy(
        role="backend",
        worktree_root=wt,
        allowed_paths=["app/**", "tests/**"],
        denied_paths=[".thread/policy.yaml"],
        allowed_shell_prefixes=["pytest", "python", "ruff", "git status", "git diff"],
    )
    ro = RolePolicy.from_scope_config("reviewer_readonly", ScopeConfig(), wt)

    # Unlisted mutating tools & unknown tools with path args must be write-checked
    for tool_name in ("delete", "unlink", "unlink_file", "move", "move_file", "rename", "fs_create", "file_save", "custom_opaque_tool"):
        with pytest.raises(ScopeViolationError):
            be.enforce_tool_call(tool_name, {"path": ".thread/policy.yaml"})

    # apply_patch Move to: and git rename to
    with pytest.raises(ScopeViolationError):
        be.enforce_tool_call(
            "apply_patch",
            {"input": "*** Begin Patch\n*** Update File: app/ok.py\n*** Move to: .thread/policy.yaml\n*** End Patch"},
        )
    with pytest.raises(ScopeViolationError):
        be.enforce_tool_call(
            "apply_patch",
            {"diff": "diff --git a/app/a.py b/.thread/policy.yaml\nrename from app/a.py\nrename to .thread/policy.yaml"},
        )

    # reviewer_readonly rejects --output and --ext-diff on git read commands
    for ro_bad in (
        "git diff --output=pwned.txt",
        "git diff --output pwned.txt",
        "git log --output=pwned.txt",
        "git show --output=pwned.txt",
        "git diff --ext-diff",
    ):
        with pytest.raises(ScopeViolationError):
            ro.enforce_shell(ro_bad)

    # backend blocks inline python -c / -Bc / node -e and --flag=outside paths
    for be_bad in (
        'python -c "open(\'.thread/policy.yaml\', \'w\').write(\'x\')"',
        'python -Bc "print(1)"',
        'python3.11 -c"print(1)"',
        'python -W ignore -c "print(1)"',
        "git diff --output=../outside.txt",
        "git diff --output .thread/policy.yaml",
        "pytest --rootdir=../outside",
    ):
        with pytest.raises(ScopeViolationError):
            be.enforce_shell(be_bad)

    # Normal commands remain allowed
    assert be.enforce_shell("pytest tests/unit/test_m1_foundation.py")
    assert be.enforce_shell("python -m pytest -c pyproject.toml")
    assert be.enforce_shell("ruff check .")
    assert be.enforce_shell("git status")
    assert be.enforce_shell("git diff")

    # Unresolved macOS symlink prefix (e.g., /var/... or symlinked parent above worktree_root)
    alias_parent = tmp_path / "alias_parent"
    real_parent = tmp_path / "real_parent"
    real_parent.mkdir()
    real_wt = real_parent / "wt"
    real_wt.mkdir()
    (real_wt / "app").mkdir()
    alias_parent.symlink_to(real_parent)
    be_alias = RolePolicy(role="backend", worktree_root=real_wt, allowed_paths=["app/**"])
    unresolved_target = str(alias_parent / "wt" / "app" / "ok.py")
    assert be_alias.enforce_write(unresolved_target) == (real_wt / "app" / "ok.py").resolve()


def test_redactor_and_event_logger_json_nested_and_env_edge_cases(tmp_path: Path) -> None:
    """Verify AWS JSON keys, CamelCase SecretAccessKey, escaped private_key, .env #, and valid EventLogger JSON."""
    aws_secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

    assert aws_secret not in redactor.redact_text(f'{{"aws_secret_access_key": "{aws_secret}"}}')
    assert aws_secret not in redactor.redact_text(f'{{"SecretAccessKey": "{aws_secret}"}}')
    assert aws_secret not in redactor.redact_json(f'{{"SecretAccessKey": "{aws_secret}"}}')

    # Safe telemetry keys remain untouched
    safe_payload = redactor.redact_payload(
        {
            "max_tokens": 4096,
            "turns_used": 3,
            "input_tokens": 100,
            "output_tokens": 50,
            "key_findings": "all good",
            "SecretAccessKey": aws_secret,
        }
    )
    assert safe_payload["max_tokens"] == 4096
    assert safe_payload["turns_used"] == 3
    assert safe_payload["input_tokens"] == 100
    assert safe_payload["output_tokens"] == 50
    assert safe_payload["key_findings"] == "all good"
    assert safe_payload["SecretAccessKey"] == "[REDACTED]"

    # Escaped GCP private_key & nested JSON inside redact_payload
    escaped_sa = '{"sa": "{\\"private_key\\": \\"SECRET_PEM_BODY\\", \\"private_key_id\\": \\"key_id_99\\"}"}'
    scrubbed_sa = redactor.redact_text(escaped_sa)
    assert "SECRET_PEM_BODY" not in scrubbed_sa
    assert "key_id_99" not in scrubbed_sa

    # Unquoted .env with '#' and escaped double quotes
    assert redactor.redact_text("DB_PASSWORD=my_pass#withhash123") == "DB_PASSWORD=[REDACTED]"
    assert redactor.redact_text('DB_PASSWORD="abc\\"def"') == 'DB_PASSWORD="[REDACTED]"'
    assert redactor.redact_text('{"env":"MY_SECRET=json_str_env_secret_99"}') == '{"env":"MY_SECRET=[REDACTED]"}'

    # EventLogger nested JSON and plain string -> always valid JSON
    db = StateDatabase(repo_root=tmp_path / "db")
    logger = EventLogger(db)
    sec = "json_str_env_secret_99"
    logger.emit("t1", "nested", json.dumps({"inner": json.dumps({"env": f"APP_SECRET={sec}"})}))
    logger.emit("t1", "quoted", f'log: {{"env":"MY_SECRET={sec}"}}')
    logger.emit("t1", "plain", f"plain DB_PASSWORD={sec}")

    with sqlite3.connect(db.db_path) as conn:
        rows = [r[0] for r in conn.execute("SELECT payload_json FROM events").fetchall()]
    assert len(rows) == 3
    for row in rows:
        assert sec not in row
        parsed = json.loads(row)
        assert isinstance(parsed, (dict, list))


def test_loader_and_worktree_minor_hardening(tmp_path: Path) -> None:
    """Verify loader rejects '-' refs and mid-path '..', and WorktreeManager rejects '.' and substring grep."""
    from thread_sdlc.config import ConfigLoadError
    from thread_sdlc.workers import WorktreeError, WorktreeManager

    repo = tmp_path / "repo"
    _init_git_repo(repo)
    with pytest.raises(ConfigLoadError):
        load_from_git_ref(repo, "--help", ".thread/policy.yaml")
    with pytest.raises(ConfigLoadError):
        load_from_git_ref(repo, "main", "foo/../../etc/passwd")

    wm = WorktreeManager(repo)
    with pytest.raises(WorktreeError):
        wm.branch_name(".", "T1")
    with pytest.raises(WorktreeError):
        wm.branch_name("..", "T1")

    (repo / "x.txt").write_text("x\n", encoding="utf-8")
    _git(["add", "x.txt"], repo)
    _git(["commit", "-m", "Commit\n\nThread-Assignment-Id: asgn-10\n\nBody"], repo)
    assert wm.find_commit_by_assignment_id("asgn-1", repo) is None
    assert wm.find_commit_by_assignment_id("asgn-10", repo) is not None


# ---------------------------------------------------------------------------
# 9. Iteration 3 Regression Tests (R2 Challenger & Polish Fixes)
# ---------------------------------------------------------------------------


def test_shell_space_separated_file_writing_flags_and_python_m_allowlist(tmp_path: Path) -> None:
    """Verify space-separated/= file-writing flags and python -m allowlist enforcement."""
    wt = tmp_path / "wt"
    wt.mkdir()
    be = RolePolicy(
        role="backend",
        worktree_root=wt,
        allowed_paths=["app/**", "tests/**"],
        denied_paths=[".thread/policy.yaml"],
        allowed_shell_prefixes=["pytest", "python", "ruff", "git status", "git diff"],
    )
    ro = RolePolicy.from_scope_config("reviewer_readonly", ScopeConfig(), wt)

    for bad_cmd in (
        "pytest --junitxml .thread/policy.yaml tests/test_ok.py",
        "pytest --log-file .thread/policy.yaml",
        "pytest --junit-xml .thread/policy.yaml",
        "pytest --basetemp=.thread/evil",
        "pytest --basetemp .thread/evil",
        "pytest --resultlog .thread/policy.yaml",
        "pytest --result-log .thread/policy.yaml",
        "pytest --cache-dir .thread/evil",
        "pytest --junitxml out.xml",
        "pytest -o cache_dir=.thread/evil",
        "pytest --override-ini=log_file=.thread/policy.yaml",
        "ruff check --output-file .thread/policy.yaml",
        "ruff check --output-file=.thread/policy.yaml",
        "ruff check -o .thread/policy.yaml",
        "ruff check -o.thread/policy.yaml",
        "git diff --output .thread/policy.yaml",
        'python -m timeit -s "open(\'.thread/policy.yaml\',\'w\').write(\'x\')" "1"',
        'python -Bm timeit -s "print(1)" "1"',
        "python -m cProfile -o .thread/policy.yaml -m pytest",
        "python -m http.server 8000",
        "python -m pip install requests",
        "python -m pytest --junitxml .thread/policy.yaml",
        "python -mpytest --basetemp .thread/evil",
        "python -m",
    ):
        with pytest.raises(ScopeViolationError):
            be.enforce_shell(bad_cmd)

    # Readonly rejects file-writing flags unconditionally
    for ro_bad in (
        "git diff --output=out.txt",
        "git log --output out.txt",
        "git show -o out.txt",
    ):
        with pytest.raises(ScopeViolationError):
            ro.enforce_shell(ro_bad)

    # Legitimate commands continue to pass
    assert be.enforce_shell("pytest tests/unit")
    assert be.enforce_shell("pytest -v")
    assert be.enforce_shell("pytest -o filterwarnings=error tests/unit")
    assert be.enforce_shell("pytest --junitxml tests/report.xml tests/unit")
    assert be.enforce_shell("python -m pytest tests/unit")
    assert be.enforce_shell("python -m unittest discover tests")
    assert be.enforce_shell("python -m ruff check .")
    assert be.enforce_shell("git diff")
    assert be.enforce_shell("ruff check .")
    assert ro.enforce_shell("git log --oneline")


def test_read_tools_paths_list_nested_keys_and_tool_args_fallback(tmp_path: Path) -> None:
    """Verify _READ_TOOLS checks paths/files/nested entries and unrecognized tools check target/link/outputFile."""
    from copilot.generated.session_events import PermissionRequestCustomTool, PermissionRequestMcp

    wt = tmp_path / "wt"
    wt.mkdir()
    be = RolePolicy(
        role="backend",
        worktree_root=wt,
        allowed_paths=["app/**", "tests/**"],
        denied_paths=[".thread/policy.yaml"],
    )
    ro = RolePolicy.from_scope_config("reviewer_readonly", ScopeConfig(), wt)

    # _READ_TOOLS paths/files/nested checks
    for policy in (be, ro):
        with pytest.raises(ScopeViolationError):
            policy.enforce_tool_call("read_file", {"paths": ["/etc/passwd"]})
        with pytest.raises(ScopeViolationError):
            policy.enforce_tool_call("grep", {"paths": ["app/", "../outside.txt"]})
        with pytest.raises(ScopeViolationError):
            policy.enforce_tool_call("view_file", {"files": [{"path": "/etc/passwd"}]})

    # In-scope _READ_TOOLS with paths list works
    be.enforce_tool_call("read_file", {"paths": ["app/main.py", "tests/test_ok.py"]})

    # Unrecognized tools with target/link/outputFile/nested paths are write-checked
    with pytest.raises(ScopeViolationError):
        be.enforce_tool_call("symlink", {"target": "/etc/passwd", "link": ".thread/policy.yaml"})
    with pytest.raises(ScopeViolationError):
        be.enforce_tool_call("custom_reporter", {"options": {"outputFile": ".thread/policy.yaml"}})
    with pytest.raises(ScopeViolationError):
        be.enforce_tool_call("custom_runner", {"junitxml": ".thread/policy.yaml"})

    # SDK PermissionRequestMcp + tool_args fallback
    sdk = CopilotSdkAdapter(be)
    mcp_req = PermissionRequestMcp(
        read_only=True,
        server_name="fs",
        tool_name="read_file",
        tool_title="Read File",
        args={"paths": ["/etc/passwd"]},
    )
    mcp_dec = asyncio.run(sdk._on_permission_request(mcp_req))
    assert getattr(mcp_dec, "kind", None) == "denied-by-rules"

    custom_req = PermissionRequestCustomTool(
        tool_description="symlink",
        tool_name="symlink",
        args={"target": "/etc/passwd", "link": ".thread/policy.yaml"},
    )
    custom_dec = asyncio.run(sdk._on_permission_request(custom_req))
    assert getattr(custom_dec, "kind", None) == "denied-by-rules"

    dict_req = {"kind": "custom-tool", "tool_name": "read_file", "tool_args": {"paths": ["/etc/passwd"]}}
    dict_dec = asyncio.run(sdk._on_permission_request(dict_req))
    assert dict_dec["kind"] == "denied-by-rules"


def test_sdk_midline_delta_buffering_and_nonjson_escaped_env_redaction(tmp_path: Path) -> None:
    """Verify SDK line-buffered delta redaction prevents split PEM/token leaks and redactor handles KEY=\\\"...\\\"."""
    repo = tmp_path / "repo"
    base_sha = _init_git_repo(repo)
    db = StateDatabase(repo_root=repo)
    sr = StateRepository(db)
    sr.create_thread(ThreadRecord(id="thr-sdk-buf", title="SDK Buf", base_sha=base_sha))
    sr.create_ticket(TicketRecord(id="T-BUF", thread_id="thr-sdk-buf", title="Buf", role="backend"))

    class _ChunkedSecretSession:
        def __init__(self) -> None:
            self._handlers: list[Any] = []

        def on(self, cb: Any) -> None:
            self._handlers.append(cb)

        async def send_and_wait(self, prompt: str, *, timeout: float = 60.0) -> None:
            chunks = [
                "-----BEGIN RSA ",
                "PRIVATE KEY-----\n",
                "MIIEow_MIDLINE_",
                "CHUNKED_SECRET\n",
                "-----END RSA PRIVATE KEY-----\n",
                "ghp_123456",
                "7890abcdef1234\n",
                "DONE_STREAM",
            ]
            for ch in chunks:
                for h in self._handlers:
                    h({"type": "assistant.message.delta", "data": {"delta_content": ch}})
            for h in self._handlers:
                h({"type": "session.idle", "data": {}})

        async def disconnect(self) -> None:
            return None

    class _ChunkedSecretClient:
        async def create_session(self, **kwargs: Any) -> _ChunkedSecretSession:
            return _ChunkedSecretSession()

    mgr = WorkerManager(
        repo_root=repo,
        db=db,
        policy=PolicyConfig(),
        scope=ScopeConfig(),
        adapter_factory=lambda pol: CopilotSdkAdapter(
            pol, client_factory=lambda: _ChunkedSecretClient()
        ),
    )
    res = asyncio.run(mgr.dispatch_ticket("thr-sdk-buf", "T-BUF", "stream"))
    assert res.log_path is not None

    log_text = (repo / res.log_path).read_text(encoding="utf-8")
    with sqlite3.connect(db.db_path) as conn:
        events_text = "\n".join(
            r[0] for r in conn.execute("SELECT payload_json FROM events").fetchall()
        )

    for forbidden in (
        "-----BEGIN RSA",
        "PRIVATE KEY-----",
        "MIIEow_MIDLINE_CHUNKED_SECRET",
        "MIIEow_MIDLINE_",
        "ghp_123456",
        "7890abcdef1234",
    ):
        assert forbidden not in log_text
        assert forbidden not in events_text
    assert "DONE_STREAM" in log_text
    assert "DONE_STREAM" in events_text

    # Non-JSON prefixed escaped quotes: log: {"env":"DB_PASSWORD=\"sec_dq_esc_1\""}
    prefixed_line = 'log: {"env":"DB_PASSWORD=\\"sec_dq_esc_1\\""}'
    scrubbed_line = redactor.redact_text(prefixed_line)
    assert "sec_dq_esc_1" not in scrubbed_line

    logger = EventLogger(db)
    logger.emit("thr-sdk-buf", "escaped_env_log", prefixed_line)
    with sqlite3.connect(db.db_path) as conn:
        last_payload = conn.execute(
            "SELECT payload_json FROM events WHERE type='escaped_env_log'"
        ).fetchone()[0]
    assert "sec_dq_esc_1" not in last_payload
    assert isinstance(json.loads(last_payload), dict)


# ---------------------------------------------------------------------------
# 10. Iteration 4 Regression Tests (R3 Challenger & Reviewer Findings)
# ---------------------------------------------------------------------------


def test_pytest_override_ini_glued_o_and_junit_logging(tmp_path: Path) -> None:
    """Verify space-separated --override-ini, glued -o<kv>, and non-path junit_logging enum."""
    wt = tmp_path / "wt"
    wt.mkdir()
    be = RolePolicy(
        role="backend",
        worktree_root=wt,
        allowed_paths=["app/**", "tests/**"],
        denied_paths=[".thread/policy.yaml"],
        deny_gate_files=["tests/acceptance/**"],
        allowed_shell_prefixes=["pytest", "python", "ruff", "git status", "git diff"],
    )
    ro = RolePolicy(
        role="reviewer_readonly",
        worktree_root=wt,
        allowed_paths=[],
        denied_paths=["**"],
        allowed_shell_prefixes=["pytest"],
        readonly=True,
    )

    for bad_cmd in (
        "pytest --override-ini log_file=.thread/policy.yaml tests/test_ok.py",
        "pytest --override-ini cache_dir=.thread/evil tests/test_ok.py",
        "pytest --override-ini log_file=../outside.log tests/test_ok.py",
        "pytest -olog_file=.thread/policy.yaml tests/test_ok.py",
        "pytest -ocache_dir=.thread/evil tests/test_ok.py",
        "python -m pytest --override-ini log_file=.thread/policy.yaml tests/test_ok.py",
        "python -m pytest --override-ini cache_dir=.thread/evil tests/test_ok.py",
        "python -m pytest -olog_file=.thread/policy.yaml tests/test_ok.py",
        "python -m pytest -ocache_dir=.thread/evil tests/test_ok.py",
        "pytest --override-ini",
    ):
        with pytest.raises(ScopeViolationError):
            be.enforce_shell(bad_cmd)

    with pytest.raises(ScopeViolationError):
        ro.enforce_shell("pytest --override-ini filterwarnings=error tests/test_ok.py")

    assert be.enforce_shell("pytest -o junit_logging=all tests/unit")
    assert be.enforce_shell("pytest --override-ini junit_logging=system-out tests/unit")
    assert be.enforce_shell("pytest -ofilterwarnings=error tests/unit")


def test_coverage_nested_module_outputs_and_ruff_mutating_commands(tmp_path: Path) -> None:
    """Verify python -m coverage nested -m/-d/-o/--data-file and ruff format/--fix protections."""
    wt = tmp_path / "wt"
    wt.mkdir()
    be = RolePolicy(
        role="backend",
        worktree_root=wt,
        allowed_paths=["app/**", "tests/**"],
        denied_paths=[".thread/policy.yaml"],
        deny_gate_files=["tests/acceptance/**"],
        allowed_shell_prefixes=["pytest", "python", "ruff", "git status", "git diff"],
    )
    ro = RolePolicy(
        role="reviewer_readonly",
        worktree_root=wt,
        allowed_paths=[],
        denied_paths=["**"],
        allowed_shell_prefixes=["python", "ruff"],
        readonly=True,
    )

    for bad_cov in (
        'python -m coverage run -m timeit -s "open(\'.thread/policy.yaml\',\'w\').write(\'x\')" "1"',
        'python -m coverage run -mtimeit -s "1" "1"',
        "python -m coverage run --module=http.server 8000",
        'python -m coverage run -c "print(1)"',
        'python -m coverage -c "print(1)"',
        "python -m coverage html -d .thread/evil",
        "python -m coverage html -d.thread/evil",
        "python -m coverage html --directory=.thread/evil",
        "python -m coverage xml -o .thread/evil.xml",
        "python -m coverage xml -o.thread/evil.xml",
        "python -m coverage json --output=.thread/evil.json",
        "python -m coverage run --data-file .thread/evil -m pytest tests/unit",
        "python -m coverage run --data-file=.thread/evil -m pytest tests/unit",
        "python -m coverage run -m pytest --override-ini log_file=.thread/policy.yaml tests/unit",
    ):
        with pytest.raises(ScopeViolationError):
            be.enforce_shell(bad_cov)

    with pytest.raises(ScopeViolationError):
        ro.enforce_shell("python -m coverage html -d tests/htmlcov")

    assert be.enforce_shell("python -m coverage run -m pytest tests/unit")
    assert be.enforce_shell("python -m coverage report -m")
    assert be.enforce_shell("python -m coverage html -d tests/htmlcov")

    for bad_ruff in (
        "ruff format tests/acceptance/test_gate.py",
        "ruff format .thread/policy.yaml",
        "ruff format tests",
        "ruff format",
        "ruff check --fix tests/acceptance/test_gate.py",
        "ruff check --fix-only .thread/policy.yaml",
        "ruff check --unsafe-fixes tests/acceptance/test_gate.py",
        "ruff --fix tests/acceptance/test_gate.py",
        "python -m ruff format tests/acceptance/test_gate.py",
        "python -m ruff check --fix .thread/policy.yaml",
    ):
        with pytest.raises(ScopeViolationError):
            be.enforce_shell(bad_ruff)

    with pytest.raises(ScopeViolationError):
        ro.enforce_shell("ruff format app/main.py")
    with pytest.raises(ScopeViolationError):
        ro.enforce_shell("ruff check --fix app/main.py")

    assert be.enforce_shell("ruff format app/main.py")
    assert be.enforce_shell("ruff check --fix --config pyproject.toml app/main.py")
    assert be.enforce_shell("ruff check .")
    assert be.enforce_shell("ruff check --output-format=json tests/acceptance/test_gate.py")


def test_read_tools_nested_dirs_file_uri_and_sdk_permission_request_url(tmp_path: Path) -> None:
    """Verify nested search_path/root/cwd, file:// vs https:// URI containment, and PermissionRequestUrl denial."""
    from copilot.generated.session_events import PermissionRequestUrl

    wt = tmp_path / "wt"
    (wt / "app").mkdir(parents=True)
    (wt / "app" / "main.py").write_text("x = 1\n", encoding="utf-8")

    be = RolePolicy(
        role="backend",
        worktree_root=wt,
        allowed_paths=["app/**", "tests/**"],
        denied_paths=[".thread/policy.yaml"],
    )
    ro = RolePolicy.from_scope_config("reviewer_readonly", ScopeConfig(), wt)

    for policy in (be, ro):
        with pytest.raises(ScopeViolationError):
            policy.enforce_tool_call("grep", {"options": {"search_path": "/etc"}})
        with pytest.raises(ScopeViolationError):
            policy.enforce_tool_call("find", {"nested": {"root": "/etc"}})
        with pytest.raises(ScopeViolationError):
            policy.enforce_tool_call("search", {"options": {"cwd": "/etc"}})
        with pytest.raises(ScopeViolationError):
            policy.enforce_tool_call("read_file", {"uri": "file:///etc/passwd"})
        with pytest.raises(ScopeViolationError):
            policy.enforce_tool_call("read_file", {"uri": "https://evil.example.com/secret"})

    # In-scope nested search_path and worktree file:// URI remain allowed for reads
    be.enforce_tool_call("grep", {"options": {"search_path": "app"}})
    be.enforce_tool_call("read_file", {"uri": (wt / "app" / "main.py").as_uri()})
    ro.enforce_tool_call("read_file", {"uri": (wt / "app" / "main.py").as_uri()})

    # SDK PermissionRequestUrl must fail closed (never approve-once)
    sdk = CopilotSdkAdapter(be)
    url_req = PermissionRequestUrl(
        intention="fetch external documentation",
        url="https://evil.example.com/exfil",
    )
    url_dec = asyncio.run(sdk._on_permission_request(url_req))
    assert getattr(url_dec, "kind", None) == "denied-by-rules"

    dict_url_dec = asyncio.run(
        sdk._on_permission_request({"kind": "url", "url": "https://evil.example.com/exfil"})
    )
    assert dict_url_dec["kind"] == "denied-by-rules"


# ---------------------------------------------------------------------------
# 11. Iteration 5 Regression Tests (R4 Reviewer & Challenger Findings)
# ---------------------------------------------------------------------------


def test_pytest_bundled_short_o_flags_and_value_flag_non_regression(tmp_path: Path) -> None:
    """Verify bundled pytest -qo/-vo/-qolog_file=... are blocked while -k/-m value flags pass."""
    wt = tmp_path / "wt"
    wt.mkdir()
    be = RolePolicy(
        role="backend",
        worktree_root=wt,
        allowed_paths=["app/**", "tests/**"],
        denied_paths=[".thread/policy.yaml"],
        deny_gate_files=["tests/acceptance/**"],
        allowed_shell_prefixes=["pytest", "python", "git status"],
    )
    ro = RolePolicy(
        role="reviewer_readonly",
        worktree_root=wt,
        allowed_paths=[],
        denied_paths=["**"],
        allowed_shell_prefixes=["pytest", "python"],
        readonly=True,
    )

    for bad_cmd in (
        "pytest -qo log_file=.thread/policy.yaml tests/test_ok.py",
        "pytest -qolog_file=.thread/policy.yaml tests/test_ok.py",
        "pytest -qo=log_file=.thread/policy.yaml tests/test_ok.py",
        "pytest -vo log_file=.thread/policy.yaml tests/test_ok.py",
        "pytest -volog_file=.thread/policy.yaml tests/test_ok.py",
        "pytest -qo=",
        'pytest -m "not slow" -qo log_file=.thread/policy.yaml tests/test_ok.py',
        "python -m pytest -qo log_file=.thread/policy.yaml tests/test_ok.py",
        "python -m pytest -qolog_file=.thread/policy.yaml tests/test_ok.py",
        "python -m coverage run --source app -m pytest -qo log_file=.thread/policy.yaml tests/test_ok.py",
        "python -m coverage run --source app -m pytest -qolog_file=.thread/policy.yaml tests/test_ok.py",
    ):
        with pytest.raises(ScopeViolationError):
            be.enforce_shell(bad_cmd)

    # Readonly blocks any bundled pytest -o override (even non-path ini)
    for ro_bad in (
        "pytest -qo junit_logging=all tests/test_ok.py",
        "pytest -vo filterwarnings=error tests/test_ok.py",
        "python -m pytest -qo junit_logging=all tests/test_ok.py",
    ):
        with pytest.raises(ScopeViolationError):
            ro.enforce_shell(ro_bad)

    # Non-regression: value-taking short flags containing 'o' in argument must pass
    assert be.enforce_shell("pytest -k test_foo tests/test_ok.py")
    assert be.enforce_shell("pytest -kfoo tests/test_ok.py")
    assert be.enforce_shell("pytest -mnot_slow tests/test_ok.py")
    assert be.enforce_shell('pytest -m "not slow" tests/test_ok.py')
    assert be.enforce_shell("pytest -qo junit_logging=all tests/test_ok.py")
    assert ro.enforce_shell("pytest -k test_foo tests/test_ok.py")


def test_ruff_pre_subcommand_value_flags_add_noqa_and_glob_dir_targets(tmp_path: Path) -> None:
    """Verify ruff --config before subcommand, --add-noqa, and **/ wildcard directory targets."""
    wt = tmp_path / "wt"
    (wt / "src").mkdir(parents=True)
    (wt / "src" / "app.py").write_text("x = 1\n", encoding="utf-8")
    (wt / "tests" / "unit").mkdir(parents=True)
    (wt / "tests" / "unit" / "test_ok.py").write_text("def test_ok(): pass\n", encoding="utf-8")

    be = RolePolicy(
        role="backend",
        worktree_root=wt,
        allowed_paths=["src/**", "tests/**"],
        denied_paths=[".thread/policy.yaml", "**/*.env", "**/migrations/**"],
        deny_gate_files=["tests/acceptance/**"],
        allowed_shell_prefixes=["ruff", "python"],
    )
    ro = RolePolicy(
        role="reviewer_readonly",
        worktree_root=wt,
        allowed_paths=[],
        denied_paths=["**"],
        allowed_shell_prefixes=["ruff", "python"],
        readonly=True,
    )

    for bad_cmd in (
        "ruff --config pyproject.toml format .thread/policy.yaml",
        "ruff --config pyproject.toml format tests/acceptance/test_gate.py",
        "python -m ruff --config pyproject.toml format tests/acceptance/test_gate.py",
        "ruff check --add-noqa .thread/policy.yaml",
        "ruff check --add-noqa tests/acceptance/test_gate.py",
        "ruff --config pyproject.toml check --add-noqa tests/acceptance/test_gate.py",
        "python -m ruff check --add-noqa .thread/policy.yaml",
        "ruff format src",
        "ruff check --fix src",
        "ruff format tests",
    ):
        with pytest.raises(ScopeViolationError):
            be.enforce_shell(bad_cmd)

    for ro_bad in (
        "ruff check --add-noqa src/app.py",
        "ruff --config pyproject.toml format src/app.py",
        "python -m ruff --config pyproject.toml format src/app.py",
    ):
        with pytest.raises(ScopeViolationError):
            ro.enforce_shell(ro_bad)

    # Explicit in-scope file targets and non-denied subdirs remain allowed
    assert be.enforce_shell("ruff format src/app.py")
    assert be.enforce_shell("ruff --config pyproject.toml format src/app.py")
    assert be.enforce_shell("ruff check --add-noqa src/app.py")
    assert be.enforce_shell("ruff check .")
    assert be.enforce_shell("ruff check tests/acceptance/test_gate.py")
    assert ro.enforce_shell("ruff check src/app.py")

    # Subdirectory without **/ wildcard denial remains allowed when no denied glob matches inside
    be_no_starstar = RolePolicy(
        role="backend",
        worktree_root=wt,
        allowed_paths=["src/**", "tests/**"],
        denied_paths=[".thread/policy.yaml"],
        deny_gate_files=["tests/acceptance/**"],
        allowed_shell_prefixes=["ruff"],
    )
    assert be_no_starstar.enforce_shell("ruff format tests/unit")
    assert be_no_starstar.enforce_shell("ruff format src")
    with pytest.raises(ScopeViolationError):
        be_no_starstar.enforce_shell("ruff format tests")


def test_sdk_fail_closed_permission_kinds_mcp_url_read_keys_and_null_uri(tmp_path: Path) -> None:
    """Verify SDK fail-closed kinds, commands/path requests, MCP url, grep_search/roots, and %00 URI."""
    from copilot.generated.session_events import (
        PermissionPromptRequestCommands,
        PermissionPromptRequestPath,
        PermissionPromptRequestPathAccessKind,
        PermissionRequestExtensionEnvAccess,
        PermissionRequestExtensionManagement,
        PermissionRequestExtensionPermissionAccess,
        PermissionRequestMcp,
        PermissionRequestMemory,
        PermissionRequestWorkflow,
    )

    wt = tmp_path / "wt"
    (wt / "app").mkdir(parents=True)
    (wt / "app" / "main.py").write_text("x = 1\n", encoding="utf-8")

    be = RolePolicy(
        role="backend",
        worktree_root=wt,
        allowed_paths=["app/**", "tests/**"],
        denied_paths=[".thread/policy.yaml"],
        allowed_shell_prefixes=["pytest", "git status"],
    )
    sdk = CopilotSdkAdapter(be)

    # Extension, workflow, memory, and unknown permission kinds must fail closed
    deny_reqs: list[Any] = [
        PermissionRequestExtensionEnvAccess(
            environment_variables=["GITHUB_TOKEN"], extension_name="ext"
        ),
        PermissionRequestExtensionPermissionAccess(
            capabilities=["fs"], extension_name="ext"
        ),
        PermissionRequestExtensionManagement(operation="install", extension_name="ext"),
        PermissionRequestWorkflow(
            approval_key="wf1",
            can_persist_approval=False,
            description="run workflow",
            name="wf",
            operation="execute",
            phases=[],
        ),
        PermissionRequestMemory(fact="secret"),
        {"kind": "future-unknown-kind", "anything": "value"},
        {"kind": ""},
        PermissionRequestMcp(
            read_only=True,
            server_name="web",
            tool_name="fetch",
            tool_title="Fetch",
            args={"url": "https://evil.example.com/secret"},
        ),
        PermissionPromptRequestCommands(
            can_offer_session_approval=False,
            command_identifiers=["rm"],
            full_command_text="rm -rf /etc/passwd",
            intention="delete system files",
        ),
        PermissionPromptRequestPath(
            access_kind=PermissionPromptRequestPathAccessKind.WRITE,
            paths=[".thread/policy.yaml"],
        ),
        PermissionPromptRequestPath(
            access_kind=PermissionPromptRequestPathAccessKind.READ,
            paths=["/etc/passwd"],
        ),
        PermissionPromptRequestPath(
            access_kind=PermissionPromptRequestPathAccessKind.SHELL,
            paths=["app/main.py"],
        ),
        {"kind": "path", "access_kind": "write", "paths": []},
        {"kind": "commands", "full_command_text": ""},
    ]
    for req in deny_reqs:
        dec = asyncio.run(sdk._on_permission_request(req))
        dec_kind = dec["kind"] if isinstance(dec, dict) else getattr(dec, "kind", None)
        assert dec_kind == "denied-by-rules", f"Expected denied-by-rules for {req!r}, got {dec!r}"

    # Valid in-scope commands and path requests succeed
    ok_cmd = PermissionPromptRequestCommands(
        can_offer_session_approval=False,
        command_identifiers=["pytest"],
        full_command_text="pytest tests/test_ok.py",
        intention="run unit tests",
    )
    ok_cmd_dec = asyncio.run(sdk._on_permission_request(ok_cmd))
    assert getattr(ok_cmd_dec, "kind", None) == "approve-once"

    ok_path_write = PermissionPromptRequestPath(
        access_kind=PermissionPromptRequestPathAccessKind.WRITE,
        paths=["app/main.py"],
    )
    ok_pw_dec = asyncio.run(sdk._on_permission_request(ok_path_write))
    assert getattr(ok_pw_dec, "kind", None) == "approve-once"

    ok_path_read = PermissionPromptRequestPath(
        access_kind=PermissionPromptRequestPathAccessKind.READ,
        paths=["app/main.py"],
    )
    ok_pr_dec = asyncio.run(sdk._on_permission_request(ok_path_read))
    assert getattr(ok_pr_dec, "kind", None) == "approve-once"

    # Unrecognized read-like tools (`grep_search`), plural keys (`roots`, `directories`, `dirs`), and %00 URI
    with pytest.raises(ScopeViolationError):
        be.enforce_tool_call("grep_search", {"options": {"search_path": "/etc"}})
    with pytest.raises(ScopeViolationError):
        be.enforce_tool_call("grep", {"roots": ["/etc"]})
    with pytest.raises(ScopeViolationError):
        be.enforce_tool_call("grep", {"directories": ["/etc"]})
    with pytest.raises(ScopeViolationError):
        be.enforce_tool_call("grep", {"dirs": ["/etc"]})
    with pytest.raises(ScopeViolationError):
        be.enforce_tool_call("fetch", {"url": "https://evil.example.com/secret"})
    with pytest.raises(ScopeViolationError):
        be.enforce_tool_call("symlink", {"target": "/etc/passwd", "link": ".thread/policy.yaml"})
    with pytest.raises(ScopeViolationError):
        be.enforce_read(f"{(wt / 'app').as_uri()}/%00evil")

    # In-scope grep_search search_path remains allowed for non-readonly role
    be.enforce_tool_call("grep_search", {"options": {"search_path": "app"}})


# ---------------------------------------------------------------------------
# 12. Iteration 6 Regression Tests (R5 Reviewer & Challenger Findings)
# ---------------------------------------------------------------------------


def test_pytest_addopts_override_and_nested_smuggling(tmp_path: Path) -> None:
    """Verify pytest -o/--override-ini addopts smuggling is blocked while safe addopts pass."""
    wt = tmp_path / "wt"
    (wt / "tests" / "unit").mkdir(parents=True)
    (wt / "tests" / "unit" / "test_ok.py").write_text("def test_ok(): pass\n", encoding="utf-8")

    be = RolePolicy(
        role="backend",
        worktree_root=wt,
        allowed_paths=["app/**", "tests/**"],
        denied_paths=[".thread/policy.yaml"],
        deny_gate_files=["tests/acceptance/**"],
        allowed_shell_prefixes=["pytest", "python"],
    )
    py_only_be = RolePolicy(
        role="backend",
        worktree_root=wt,
        allowed_paths=["app/**", "tests/**"],
        denied_paths=[".thread/policy.yaml"],
        allowed_shell_prefixes=["python -m pytest"],
    )
    ro = RolePolicy(
        role="reviewer_readonly",
        worktree_root=wt,
        allowed_paths=[],
        denied_paths=["**"],
        allowed_shell_prefixes=["pytest", "python"],
        readonly=True,
    )

    for bad_cmd in (
        'pytest -o addopts="--log-file=.thread/policy.yaml" tests/unit/test_ok.py',
        'pytest -o addopts="--log-file .thread/policy.yaml" tests/unit/test_ok.py',
        'pytest -o addopts="--junitxml=.thread/policy.yaml" tests/unit/test_ok.py',
        'pytest -o addopts="--junit-xml=.thread/policy.yaml" tests/unit/test_ok.py',
        'pytest -o addopts="--basetemp=.thread/evil" tests/unit/test_ok.py',
        'pytest -o addopts="--cache-dir=.thread/evil" tests/unit/test_ok.py',
        'pytest -o addopts="--resultlog=.thread/policy.yaml" tests/unit/test_ok.py',
        'pytest -o addopts="--rootdir=.thread/evil" tests/unit/test_ok.py',
        'pytest -o addopts="-c .thread/evil.ini" tests/unit/test_ok.py',
        'pytest -o addopts="-vc pyproject.toml" tests/unit/test_ok.py',
        'pytest -o addopts="--debug=.thread/policy.yaml" tests/unit/test_ok.py',
        'pytest -o addopts="-o log_file=.thread/policy.yaml" tests/unit/test_ok.py',
        'pytest -o addopts="-qo log_file=.thread/policy.yaml" tests/unit/test_ok.py',
        'pytest -o addopts="-o addopts=--log-file=.thread/policy.yaml" tests/unit/test_ok.py',
        'pytest -o addopts="-qo addopts=--junitxml=.thread/policy.yaml" tests/unit/test_ok.py',
        'pytest -o addopts="--override-ini addopts=--basetemp=.thread/evil" tests/unit/test_ok.py',
        'pytest -qo addopts="--log-file=.thread/policy.yaml" tests/unit/test_ok.py',
        'pytest --override-ini addopts="--basetemp=.thread/evil" tests/unit/test_ok.py',
        'pytest --override-ini=addopts="--junitxml=.thread/policy.yaml" tests/unit/test_ok.py',
        'pytest -oaddopts="--log-file=.thread/policy.yaml" tests/unit/test_ok.py',
        'python -m pytest -o addopts="--log-file=.thread/policy.yaml" tests/unit/test_ok.py',
        'python -m coverage run -m pytest -o addopts="--log-file=.thread/policy.yaml" tests/unit/test_ok.py',
        "pytest -o 'addopts=-v; rm -rf /' tests/unit/test_ok.py",
        "pytest -o addopts='\"unclosed' tests/unit/test_ok.py",
        'pytest -o addopts="../outside" tests/unit/test_ok.py',
    ):
        with pytest.raises(ScopeViolationError):
            be.enforce_shell(bad_cmd)

    with pytest.raises(ScopeViolationError):
        ro.enforce_shell('pytest -o addopts="-v -k test_foo" tests/unit/test_ok.py')

    # Legitimate safe addopts pass cleanly (including prefix-restricted python -m pytest)
    assert be.enforce_shell('pytest -o addopts="-v -k test_foo" tests/unit/test_ok.py')
    assert be.enforce_shell('pytest -o addopts="" tests/unit/test_ok.py')
    assert be.enforce_shell('pytest -o addopts="-p no:cacheprovider -W ignore" tests/unit/test_ok.py')
    assert py_only_be.enforce_shell(
        'python -m pytest -o addopts="-v -k test_foo" tests/unit/test_ok.py'
    )


def test_sdk_hoisted_sandbox_checks_write_new_contents_read_resolved_and_shell_paths(
    tmp_path: Path,
) -> None:
    """Verify hoisted sandbox flags/grants, write new_file_contents/file_edits, read resolved_path, and shell paths."""
    from copilot.generated.session_events import (
        PermissionPromptRequestCommands,
        PermissionPromptRequestPath,
        PermissionPromptRequestPathAccessKind,
        PermissionRequestMcp,
        PermissionRequestRead,
        PermissionRequestShell,
        PermissionRequestWrite,
        PermissionSandboxPathGrant,
        PermissionSandboxPathGrantAccess,
        PermissionWriteFileContent,
        PermissionWriteFileEdit,
    )

    wt = tmp_path / "wt"
    (wt / "app").mkdir(parents=True)
    (wt / "app" / "main.py").write_text("x = 1\n", encoding="utf-8")
    (wt / "tests" / "unit").mkdir(parents=True)

    be = RolePolicy(
        role="backend",
        worktree_root=wt,
        allowed_paths=["app/**", "tests/**"],
        denied_paths=[".thread/policy.yaml"],
        allowed_shell_prefixes=["pytest", "git status"],
    )
    ro = RolePolicy(
        role="reviewer_readonly",
        worktree_root=wt,
        allowed_paths=[],
        denied_paths=["**"],
        allowed_shell_prefixes=["pytest", "git status"],
        readonly=True,
    )
    sdk_be = CopilotSdkAdapter(be)
    sdk_ro = CopilotSdkAdapter(ro)

    deny_reqs: list[Any] = [
        PermissionRequestWrite(
            can_offer_session_approval=False,
            diff="+x",
            file_name="app/main.py",
            intention="write",
            request_sandbox_bypass=True,
        ),
        {
            "kind": "write",
            "file_name": "app/main.py",
            "request_sandbox_permissive": True,
        },
        PermissionRequestWrite(
            can_offer_session_approval=False,
            diff="+x",
            file_name="app/main.py",
            intention="write",
            sandbox_path_grant=PermissionSandboxPathGrant(
                access=PermissionSandboxPathGrantAccess.READ_WRITE,
                path=".thread/policy.yaml",
            ),
        ),
        PermissionRequestWrite(
            can_offer_session_approval=False,
            diff="+x",
            file_name="app/main.py",
            intention="write",
            sandbox_path_grant=PermissionSandboxPathGrant(
                access=PermissionSandboxPathGrantAccess.READ_WRITE,
                path="",
            ),
        ),
        PermissionRequestWrite(
            can_offer_session_approval=False,
            diff="+x",
            file_name="app/main.py",
            intention="write",
            new_file_contents=[PermissionWriteFileContent(content="evil", path=".thread/policy.yaml")],  # type: ignore[arg-type]
        ),
        PermissionRequestWrite(
            can_offer_session_approval=False,
            diff="+x",
            file_name="app/main.py",
            intention="write",
            new_file_contents=[{"content": "evil"}],  # type: ignore[arg-type]
        ),
        PermissionRequestWrite(
            can_offer_session_approval=False,
            diff="+x",
            file_name="app/main.py",
            intention="write",
            file_edits=[
                PermissionWriteFileEdit(
                    after=PermissionWriteFileContent(content="evil", path=".thread/policy.yaml")
                )
            ],
        ),
        PermissionRequestRead(
            intention="read",
            path="app/main.py",
            resolved_path="/etc/passwd",
        ),
        PermissionRequestRead(
            intention="read",
            path="app/main.py",
            request_sandbox_bypass=True,
        ),
        PermissionRequestRead(
            intention="read",
            path="app/main.py",
            sandbox_path_grant=PermissionSandboxPathGrant(
                access=PermissionSandboxPathGrantAccess.READ,
                path="/etc/shadow",
            ),
        ),
        PermissionRequestRead(
            intention="read",
            path="app/main.py",
            sandbox_path_grant=PermissionSandboxPathGrant(
                access=PermissionSandboxPathGrantAccess.READ_WRITE,
                path=".thread/policy.yaml",
            ),
        ),
        PermissionRequestShell(
            can_offer_session_approval=False,
            commands=[],
            full_command_text="pytest tests/unit",
            has_write_file_redirection=False,
            intention="run tests",
            possible_paths=[],
            possible_urls=[],
            request_sandbox_permissive=True,
        ),
        PermissionRequestShell(
            can_offer_session_approval=False,
            commands=[],
            full_command_text="pytest tests/unit",
            has_write_file_redirection=False,
            intention="run tests",
            possible_paths=["/etc/passwd"],
            possible_urls=[],
        ),
        PermissionRequestShell(
            can_offer_session_approval=False,
            commands=[],
            full_command_text="pytest tests/unit",
            has_write_file_redirection=False,
            intention="run tests",
            possible_paths=["tests/unit"],
            possible_urls=[],
            resolved_paths={"tests/unit": "/etc/passwd"},
        ),
        PermissionRequestShell(
            can_offer_session_approval=False,
            commands=[],
            full_command_text="pytest tests/unit",
            has_write_file_redirection=True,
            intention="redirect output",
            possible_paths=[".thread/policy.yaml"],
            possible_urls=[],
        ),
        PermissionRequestShell(
            can_offer_session_approval=False,
            commands=[],
            full_command_text="pytest tests/unit",
            has_write_file_redirection=True,
            intention="redirect without paths",
            possible_paths=[],
            possible_urls=[],
            resolved_paths=None,
        ),
        PermissionPromptRequestCommands(
            can_offer_session_approval=False,
            command_identifiers=["pytest"],
            full_command_text="pytest tests/unit",
            intention="run tests",
            request_sandbox_bypass=True,
        ),
        {
            "kind": "path",
            "access_kind": "read",
            "paths": ["app/main.py"],
            "request_sandbox_bypass": True,
        },
        PermissionRequestShell(
            can_offer_session_approval=False,
            commands=[],
            full_command_text="pytest tests/unit",
            has_write_file_redirection=False,
            intention="run tests",
            possible_paths=[],
            possible_urls=[],
            resolved_paths={"/etc/passwd": ""},
        ),
        PermissionRequestMcp(
            read_only=True,
            server_name="web",
            tool_name="fetch",
            tool_title="Fetch",
            args={"urls": ["https://evil.example.com/secret"]},
        ),
        PermissionRequestMcp(
            read_only=True,
            server_name="web",
            tool_name="fetch",
            tool_title="Fetch",
            args={"uris": ["https://evil.example.com/secret"]},
        ),
    ]
    for req in deny_reqs:
        dec = asyncio.run(sdk_be._on_permission_request(req))
        dec_kind = dec["kind"] if isinstance(dec, dict) else getattr(dec, "kind", None)
        assert dec_kind == "denied-by-rules", f"Expected denied-by-rules for {req!r}, got {dec!r}"

    # Read-only policy must reject shell write redirection even for otherwise allowed paths
    ro_redir = PermissionRequestShell(
        can_offer_session_approval=False,
        commands=[],
        full_command_text="pytest tests/unit",
        has_write_file_redirection=True,
        intention="redirect output",
        possible_paths=["app/out.txt"],
        possible_urls=[],
    )
    ro_dec = asyncio.run(sdk_ro._on_permission_request(ro_redir))
    assert getattr(ro_dec, "kind", None) == "denied-by-rules"

    # Non-regression: legitimate PermissionRequestWrite / Read / Shell pass cleanly
    ok_reqs: list[Any] = [
        PermissionRequestWrite(
            can_offer_session_approval=False,
            diff="+x = 2",
            file_name="app/main.py",
            intention="write",
            new_file_contents="x = 2\n",
        ),
        PermissionRequestWrite(
            can_offer_session_approval=False,
            diff="+y = 2",
            file_name="app/main.py",
            intention="write",
            new_file_contents=[PermissionWriteFileContent(content="y = 2\n", path="app/other.py")],  # type: ignore[arg-type]
        ),
        PermissionRequestRead(
            intention="read",
            path="app/main.py",
            resolved_path=str(wt / "app" / "main.py"),
            sandbox_path_grant=PermissionSandboxPathGrant(
                access=PermissionSandboxPathGrantAccess.READ,
                path="app/main.py",
            ),
        ),
        PermissionRequestShell(
            can_offer_session_approval=False,
            commands=[],
            full_command_text="pytest tests/unit",
            has_write_file_redirection=False,
            intention="run tests",
            possible_paths=[],
            possible_urls=[],
            resolved_paths=None,
        ),
        PermissionRequestShell(
            can_offer_session_approval=False,
            commands=[],
            full_command_text="pytest tests/unit",
            has_write_file_redirection=False,
            intention="run tests",
            possible_paths=["tests/unit"],
            possible_urls=[],
            resolved_paths={"tests/unit": str(wt / "tests" / "unit")},
        ),
        PermissionRequestShell(
            can_offer_session_approval=False,
            commands=[],
            full_command_text="pytest tests/unit",
            has_write_file_redirection=True,
            intention="redirect output in scope",
            possible_paths=["app/out.txt"],
            possible_urls=[],
        ),
        PermissionPromptRequestPath(
            access_kind=PermissionPromptRequestPathAccessKind.READ,
            paths=["app/main.py"],
        ),
    ]
    for ok_req in ok_reqs:
        ok_dec = asyncio.run(sdk_be._on_permission_request(ok_req))
        assert getattr(ok_dec, "kind", None) == "approve-once", (
            f"Expected approve-once for {ok_req!r}, got {ok_dec!r}"
        )


def test_read_search_extra_path_keys_containment(tmp_path: Path) -> None:
    """Verify grep_search search_paths/searchPaths/folder/folders/root_dir/rootDir enforce containment."""
    wt = tmp_path / "wt"
    (wt / "app").mkdir(parents=True)
    (wt / "app" / "main.py").write_text("x = 1\n", encoding="utf-8")

    be = RolePolicy(
        role="backend",
        worktree_root=wt,
        allowed_paths=["app/**", "tests/**"],
        denied_paths=[".thread/policy.yaml"],
    )

    for bad_args in (
        {"options": {"search_paths": ["/etc"]}},
        {"options": {"searchPaths": ["/etc"]}},
        {"folder": "/etc"},
        {"folders": ["/etc"]},
        {"root_dir": "/etc"},
        {"rootDir": "/etc"},
    ):
        with pytest.raises(ScopeViolationError):
            be.enforce_tool_call("grep_search", bad_args)

    # In-scope read/search paths remain allowed for non-readonly role
    be.enforce_tool_call("grep_search", {"options": {"search_paths": ["app"]}})
    be.enforce_tool_call("grep_search", {"folder": "app"})
    be.enforce_tool_call("grep_search", {"root_dir": "app"})


# ---------------------------------------------------------------------------
# 13. Iteration 7 Regression Tests (R6 Verifier Findings 1-4)
# ---------------------------------------------------------------------------


def test_pytest_outer_debug_flag_blocked(tmp_path: Path) -> None:
    """Verify outer pytest --debug / --debug=<file> / --debug <file> are blocked across roles."""
    wt = tmp_path / "wt"
    (wt / "tests" / "unit").mkdir(parents=True)
    (wt / ".thread").mkdir(parents=True)
    (wt / ".thread" / "policy.yaml").write_text("base_branch: main\n", encoding="utf-8")
    (wt / "tests" / "unit" / "test_ok.py").write_text("def test_ok(): pass\n", encoding="utf-8")

    be = RolePolicy(
        role="backend",
        worktree_root=wt,
        allowed_paths=["app/**", "tests/**"],
        denied_paths=[".thread/policy.yaml", ".thread/**"],
        allowed_shell_prefixes=["pytest", "python"],
    )
    ro = RolePolicy(
        role="reviewer_readonly",
        worktree_root=wt,
        allowed_paths=[],
        denied_paths=["**"],
        allowed_shell_prefixes=["pytest", "python"],
        readonly=True,
    )

    for cmd in (
        "pytest --debug=.thread/policy.yaml tests/unit/test_ok.py",
        "pytest --debug .thread/policy.yaml tests/unit/test_ok.py",
        "pytest tests/unit/test_ok.py --debug",
        "pytest --debug= tests/unit/test_ok.py",
        "python -m pytest --debug=.thread/policy.yaml tests/unit/test_ok.py",
        "python -m coverage run -m pytest --debug=.thread/policy.yaml tests/unit/test_ok.py",
    ):
        with pytest.raises(ScopeViolationError):
            be.enforce_shell(cmd)
        with pytest.raises(ScopeViolationError):
            ro.enforce_shell(cmd)

    # Coverage's own --debug=<topic> before `-m pytest` remains allowed for writable roles
    assert be.enforce_shell("python -m coverage run --debug=trace -m pytest tests/unit/test_ok.py")


def test_pytest_config_file_and_bundled_c_containment(tmp_path: Path) -> None:
    """Verify pytest -c / --config-file / bundled -vc/-qc / --rootdir smuggling is blocked while valid root configs pass."""
    wt = tmp_path / "wt"
    (wt / "app").mkdir(parents=True)
    (wt / "tests" / "unit").mkdir(parents=True)
    (wt / ".thread").mkdir(parents=True)
    (wt / ".thread" / "policy.yaml").write_text("base_branch: main\n", encoding="utf-8")
    (wt / "tests" / "unit" / "test_ok.py").write_text("def test_ok(): pass\n", encoding="utf-8")
    (wt / "app" / "evil.ini").write_text(
        "[pytest]\naddopts = --log-file=.thread/policy.yaml\n", encoding="utf-8"
    )
    (wt / "app" / "pytest.ini").write_text(
        "[pytest]\naddopts = --log-file=.thread/policy.yaml\n", encoding="utf-8"
    )
    (wt / "tests" / "evil.ini").write_text(
        "[pytest]\naddopts = --junitxml=.thread/policy.yaml\n", encoding="utf-8"
    )

    be = RolePolicy(
        role="backend",
        worktree_root=wt,
        allowed_paths=["app/**", "tests/**"],
        denied_paths=[".thread/policy.yaml", ".thread/**"],
        allowed_shell_prefixes=["pytest", "python"],
    )

    # Non-regression when pyproject.toml is absent on disk (empty tmp_path)
    assert be.enforce_shell("python -m pytest -c pyproject.toml")
    assert be.enforce_shell("pytest -vcpyproject.toml tests/unit/test_ok.py")
    assert be.enforce_shell("pytest -kc tests/unit/test_ok.py")

    for bad_cmd in (
        "pytest -vc/outside/evil.ini tests/unit/test_ok.py",
        "pytest -qc ../outside/evil.ini tests/unit/test_ok.py",
        "pytest -c /etc/evil.ini tests/unit/test_ok.py",
        "pytest --config-file /outside/evil.ini tests/unit/test_ok.py",
        "pytest --config-file=/outside/evil.ini tests/unit/test_ok.py",
        "pytest -c app/evil.ini tests/unit/test_ok.py",
        "pytest --config-file=app/evil.ini tests/unit/test_ok.py",
        "pytest --config-file app/evil.ini tests/unit/test_ok.py",
        "pytest -capp/evil.ini tests/unit/test_ok.py",
        "pytest -c=app/evil.ini tests/unit/test_ok.py",
        "pytest -qc app/evil.ini tests/unit/test_ok.py",
        "pytest -qc=tests/evil.ini tests/unit/test_ok.py",
        "pytest -vcapp/evil.ini tests/unit/test_ok.py",
        "pytest --rootdir=app tests/unit/test_ok.py",
        "pytest --rootdir app tests/unit/test_ok.py",
        "pytest -c",
        "pytest --config-file",
        "pytest -qc",
        "pytest -c=",
        "pytest -qc=",
        "pytest --config-file=",
        "pytest --rootdir",
    ):
        with pytest.raises(ScopeViolationError):
            be.enforce_shell(bad_cmd)

    # Malicious on-disk root configs must be rejected
    (wt / "pytest.ini").write_text(
        "[pytest]\naddopts = --log-file=.thread/policy.yaml\n", encoding="utf-8"
    )
    with pytest.raises(ScopeViolationError):
        be.enforce_shell("pytest -c pytest.ini tests/unit/test_ok.py")
    (wt / "pytest.ini").unlink()

    (wt / "pyproject.toml").write_text(
        '[tool.pytest.ini_options]\naddopts = ["--junitxml=.thread/policy.yaml"]\n',
        encoding="utf-8",
    )
    with pytest.raises(ScopeViolationError):
        be.enforce_shell("pytest -c pyproject.toml tests/unit/test_ok.py")

    (wt / "pyproject.toml").write_text(
        '[tool.pytest.ini_options]\nlog_file = ".thread/policy.yaml"\n',
        encoding="utf-8",
    )
    with pytest.raises(ScopeViolationError):
        be.enforce_shell("pytest -vcpyproject.toml tests/unit/test_ok.py")

    (wt / "pyproject.toml").write_text("[broken toml ===\n", encoding="utf-8")
    with pytest.raises(ScopeViolationError):
        be.enforce_shell("pytest --config-file=pyproject.toml tests/unit/test_ok.py")

    # Benign on-disk pyproject.toml passes across all valid -c / --config-file forms
    (wt / "pyproject.toml").write_text(
        '[tool.pytest.ini_options]\ntestpaths = ["tests"]\npythonpath = ["src"]\naddopts = "-v -k test_ok"\n',
        encoding="utf-8",
    )
    assert be.enforce_shell("python -m pytest -c pyproject.toml tests/unit/test_ok.py")
    assert be.enforce_shell("pytest -vcpyproject.toml tests/unit/test_ok.py")
    assert be.enforce_shell("pytest -qc pyproject.toml tests/unit/test_ok.py")
    assert be.enforce_shell("pytest --config-file=pyproject.toml tests/unit/test_ok.py")
    assert be.enforce_shell("pytest -c=pyproject.toml tests/unit/test_ok.py")


def test_pytest_override_ini_multipath_containment(tmp_path: Path) -> None:
    """Verify space-separated multi-path values in pytest -o ini overrides enforce containment."""
    wt = tmp_path / "wt"
    (wt / "tests" / "unit").mkdir(parents=True)
    (wt / "tests" / "integration").mkdir(parents=True)
    (wt / "tests" / "unit" / "test_ok.py").write_text("def test_ok(): pass\n", encoding="utf-8")

    be = RolePolicy(
        role="backend",
        worktree_root=wt,
        allowed_paths=["app/**", "tests/**"],
        denied_paths=[".thread/policy.yaml"],
        allowed_shell_prefixes=["pytest"],
    )

    for bad_cmd in (
        'pytest -o "testpaths=tests/unit /outside" tests/unit/test_ok.py',
        'pytest -o "pythonpath=src ../outside" tests/unit/test_ok.py',
        'pytest -o "norecursedirs=build /etc" tests/unit/test_ok.py',
        'pytest -o \'testpaths="tests/unit" "/outside"\' tests/unit/test_ok.py',
        'pytest -o "testpaths=tests/unit https://evil.example.com" tests/unit/test_ok.py',
    ):
        with pytest.raises(ScopeViolationError):
            be.enforce_shell(bad_cmd)

    assert be.enforce_shell('pytest -o "testpaths=tests/unit tests/integration" tests/unit/test_ok.py')


def test_sdk_shell_resolved_paths_dict_key_shadowing_and_possible_urls(tmp_path: Path) -> None:
    """Verify SDK _extract_shell_paths handles 'path' key shadowing and PermissionRequestShell.possible_urls fails closed."""
    from copilot.generated.session_events import (
        PermissionRequestShell,
        PermissionRequestShellPossibleUrl,
    )

    wt = tmp_path / "wt"
    (wt / "app").mkdir(parents=True)
    (wt / "app" / "main.py").write_text("x = 1\n", encoding="utf-8")
    (wt / "tests" / "unit").mkdir(parents=True)

    be = RolePolicy(
        role="backend",
        worktree_root=wt,
        allowed_paths=["app/**", "tests/**"],
        denied_paths=[".thread/policy.yaml"],
        allowed_shell_prefixes=["pytest"],
    )
    sdk_be = CopilotSdkAdapter(be)

    deny_reqs: list[Any] = [
        PermissionRequestShell(
            can_offer_session_approval=False,
            commands=[],
            full_command_text="pytest tests/unit",
            has_write_file_redirection=False,
            intention="run tests",
            possible_paths=[],
            possible_urls=[],
            resolved_paths={"path": "app/main.py", "evil": "/etc/passwd"},
        ),
        PermissionRequestShell(
            can_offer_session_approval=False,
            commands=[],
            full_command_text="pytest tests/unit",
            has_write_file_redirection=False,
            intention="run tests",
            possible_paths=[],
            possible_urls=[],
            resolved_paths={"path": "app/main.py", "resolvedPath": "/etc/passwd"},
        ),
        PermissionRequestShell(
            can_offer_session_approval=False,
            commands=[],
            full_command_text="pytest tests/unit",
            has_write_file_redirection=False,
            intention="run tests",
            possible_paths=[],
            possible_urls=[PermissionRequestShellPossibleUrl(url="https://evil.example.com")],
        ),
        {
            "kind": "shell",
            "fullCommandText": "pytest tests/unit",
            "possiblePaths": [],
            "possibleUrls": [{"url": "https://evil.example.com"}],
        },
    ]
    for req in deny_reqs:
        dec = asyncio.run(sdk_be._on_permission_request(req))
        dec_kind = dec["kind"] if isinstance(dec, dict) else getattr(dec, "kind", None)
        assert dec_kind == "denied-by-rules", f"Expected denied-by-rules for {req!r}, got {dec!r}"

    ok_reqs: list[Any] = [
        PermissionRequestShell(
            can_offer_session_approval=False,
            commands=[],
            full_command_text="pytest tests/unit",
            has_write_file_redirection=False,
            intention="run tests",
            possible_paths=[],
            possible_urls=[],
            resolved_paths={"path": "app/main.py", "tests": str(wt / "tests" / "unit")},
        ),
        {
            "kind": "shell",
            "full_command_text": "pytest tests/unit",
            "possible_paths": [{"path": "app/main.py", "content": "ok"}],
            "possible_urls": [],
        },
    ]
    for req in ok_reqs:
        dec = asyncio.run(sdk_be._on_permission_request(req))
        dec_kind = dec["kind"] if isinstance(dec, dict) else getattr(dec, "kind", None)
        expected_kind = "approved" if isinstance(req, dict) else "approve-once"
        assert dec_kind == expected_kind, f"Expected {expected_kind} for {req!r}, got {dec!r}"
