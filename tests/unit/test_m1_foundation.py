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
