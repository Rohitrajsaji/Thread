"""Release gate for local approval authorization and worker safety controls."""

import asyncio
from pathlib import Path
import subprocess

from fastapi.testclient import TestClient
import pytest

from thread_sdlc.cli.doctor import run_spike_diagnostics
from thread_sdlc.compiler.engine import apply
from thread_sdlc.config import PolicyConfig, ScopeConfig
from thread_sdlc.state import StateDatabase, StateRepository, ThreadRecord, TicketRecord
from thread_sdlc.ui.api import create_app
from thread_sdlc.workers import MockWorkerAdapter, PausedQuota, RolePolicy, ScopeViolationError
from thread_sdlc.workers.adapter import WorkerEvent
from thread_sdlc.workers.manager import WorkerManager


@pytest.mark.parametrize(
    ("endpoint", "payload"),
    [
        ("/api/checkpoints/example/decide", {
            "decision": "approved", "content_sha256": "a" * 64, "git_head_sha": "b" * 40,
        }),
        ("/api/tickets/example/merge", {"expected_head": "b" * 40, "expected_base": "c" * 40}),
    ],
)
def test_approval_and_merge_require_authentication_and_local_origin(
    tmp_path: Path, endpoint: str, payload: dict[str, str],
) -> None:
    apply(tmp_path, initialize=True)
    origin = "http://127.0.0.1:4242"
    with TestClient(create_app(tmp_path, "fixture-token", 4242), base_url=origin) as client:
        assert client.post(endpoint, headers={"Origin": origin}, json=payload).status_code == 401
        rejected_launch = client.get("/", params={"token": "invalid"}, follow_redirects=False)
        assert rejected_launch.status_code == 401
        launch = client.get("/", params={"token": "fixture-token"}, follow_redirects=False)
        assert launch.status_code == 303
        assert launch.headers["location"] == "/"
        cookie = launch.headers["set-cookie"].lower()
        assert "httponly" in cookie and "samesite=strict" in cookie
        assert client.get("/", params={"token": "fixture-token"}, follow_redirects=False).status_code == 401
        assert client.get("/api/auth/session").status_code == 200
        assert client.post(endpoint, headers={"Origin": "http://example.test"}, json=payload).status_code == 403
        assert client.post(endpoint, json=payload).status_code == 403
        assert client.post(
            endpoint,
            headers={"Host": "example.test:4242", "Origin": origin},
            json=payload,
        ).status_code == 403
        # Correctly authenticated local requests reach the route and look up the object.
        assert client.post(endpoint, headers={"Origin": origin}, json=payload).status_code == 404


def test_both_worker_adapters_enforce_scope_before_write(tmp_path: Path) -> None:
    # The spike drives the SDK hook and a real CLI hook subprocess with a
    # simulated Copilot transport, and verifies the denied file never appears.
    report = run_spike_diagnostics(tmp_path)
    assert len(report.comparison) == 2
    for result in report.comparison:
        assert result.pre_write_scope_block == "PASS", result
    assert all(row.quota_handling == "PASS" for row in report.comparison)


def test_readonly_worker_accepts_inspection_but_refuses_mutation(tmp_path: Path) -> None:
    policy = RolePolicy(
        role="reviewer_readonly", worktree_root=tmp_path, readonly=True,
        allowed_shell_prefixes=["git"],
    )
    assert policy.enforce_shell("git status --short")
    with pytest.raises(ScopeViolationError):
        policy.enforce_write("note.txt")
    with pytest.raises(ScopeViolationError):
        policy.enforce_shell("git add note.txt")
    assert not (tmp_path / "note.txt").exists()


@pytest.fixture
def worker_repo(tmp_path: Path) -> tuple[StateDatabase, StateRepository]:
    subprocess.run(["git", "init", "-q", "-b", "main", str(tmp_path)], check=True)
    subprocess.run([
        "git", "-c", "user.name=Thread test", "-c", "user.email=thread@example.test",
        "commit", "-qm", "Initial test baseline", "--allow-empty",
    ], cwd=tmp_path, check=True)
    sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=tmp_path, text=True).strip()
    db = StateDatabase(repo_root=tmp_path)
    records = StateRepository(db)
    records.create_thread(ThreadRecord(id="thread", title="Safety gate", base_sha=sha))
    records.create_ticket(TicketRecord(id="ticket", thread_id="thread", title="Test adapter", role="backend"))
    return db, records


def test_worker_stdout_is_redacted_before_log_and_database_writes(
    tmp_path: Path, worker_repo: tuple[StateDatabase, StateRepository],
) -> None:
    fake_secret = "gate_fixture_secret_value"

    class RawStdoutAdapter(MockWorkerAdapter):
        async def stream_events(self):
            yield WorkerEvent(type="stdout", message=f"DB_PASSWORD={fake_secret}")

    db, _ = worker_repo
    manager = WorkerManager(
        repo_root=tmp_path, db=db, policy=PolicyConfig(), scope=ScopeConfig(),
        adapter_factory=RawStdoutAdapter,
    )
    outcome = asyncio.run(manager.dispatch_ticket("thread", "ticket", "Run the fixture"))
    log_content = (tmp_path / outcome.log_path).read_text()
    with db.read_connection() as connection:
        event = connection.execute("SELECT payload_json FROM events WHERE type = 'worker.stdout'").fetchone()
    assert event is not None
    for content in (log_content, event["payload_json"]):
        assert "DB_PASSWORD=[REDACTED]" in content
        assert fake_secret not in content


def test_paused_quota_is_persisted_and_prevents_worker_restart(
    tmp_path: Path, worker_repo: tuple[StateDatabase, StateRepository],
) -> None:
    db, records = worker_repo
    started: list[MockWorkerAdapter] = []

    def adapter_factory(policy: RolePolicy) -> MockWorkerAdapter:
        adapter = MockWorkerAdapter(policy, scenario="quota_exceeded", quota_mode="provider")
        started.append(adapter)
        return adapter

    manager = WorkerManager(
        repo_root=tmp_path, db=db, policy=PolicyConfig(), scope=ScopeConfig(),
        adapter_factory=adapter_factory,
    )
    with pytest.raises(PausedQuota):
        asyncio.run(manager.dispatch_ticket("thread", "ticket", "Run the fixture"))
    thread = records.get_thread("thread")
    assert thread is not None and thread.status == "PausedQuota"
    with pytest.raises(PausedQuota):
        asyncio.run(manager.dispatch_ticket("thread", "ticket", "Try restarting"))
    assert [adapter.start_count for adapter in started] == [1]
