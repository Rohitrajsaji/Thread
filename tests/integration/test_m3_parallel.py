import asyncio
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from thread_sdlc.compiler.engine import apply
from thread_sdlc.orchestrator.engine import InvalidTransitionError, Workflow
from thread_sdlc.workers.adapter import MockWorkerAdapter


def git(root, *args):
    return subprocess.check_output(["git", *args], cwd=root, text=True).strip()


@pytest.fixture
def inventory(tmp_path):
    source = Path(__file__).parents[2] / "examples" / "inventory-app"
    root = tmp_path / "inventory"
    shutil.copytree(source, root, ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache", ".DS_Store"))
    git(root, "init", "-q", "-b", "main")
    git(root, "config", "user.name", "Thread Test")
    git(root, "config", "user.email", "test@example.test")
    apply(root, initialize=True)
    (root / ".gitignore").write_text(".thread-state/\n")
    for name, update in (
        ("config", {"adapter": "mock", "features": {"m3a": True, "m3b": True}}),
        ("policy", {"caps": {"max_workers_per_thread": 2, "max_goldfish_reviews": 3}}),
    ):
        path = root / ".thread" / f"{name}.yaml"
        raw = yaml.safe_load(path.read_text())
        raw.update(update)
        path.write_text(yaml.safe_dump(raw))
    git(root, "add", ".")
    git(root, "commit", "-qm", "Inventory baseline")
    return root


class Farm(Workflow):
    def __init__(self, root, files, *, simultaneous=False):
        super().__init__(root)
        self.files = files
        self.simultaneous = simultaneous
        self.started = {}
        self.ready = asyncio.Event()

    def _adapter(self, policy):
        farm = self

        class Adapter(MockWorkerAdapter):
            async def start(self, assignment):
                self.allowed_file_relpath, self.allowed_content = farm.files[assignment.ticket_id]
                farm.started[assignment.ticket_id] = assignment.base_sha
                if assignment.ticket_id == "join":
                    assert (assignment.worktree_path / "app/api_note.py").is_file()
                    assert (assignment.worktree_path / "frontend/banner.txt").is_file()
                await super().start(assignment)
                if farm.simultaneous and assignment.ticket_id in {"api", "ui"}:
                    if {"api", "ui"} <= farm.started.keys():
                        farm.ready.set()
                    await asyncio.wait_for(farm.ready.wait(), 5)

        return Adapter(policy)


def register(farm, files, *, dependent=False, roles=None):
    thread = farm.start_or_resume("Fix typo in inventory messages")["thread"]
    farm.plan_tickets(thread["id"], [
        {"id": key, "title": key, "role": (roles or {}).get(key, "backend"),
         "paths": [path], "depends_on": ["api", "ui"] if dependent and key == "join" else []}
        for key, (path, _) in files.items()
    ])
    return thread["id"], thread["base_sha"]


def test_parallel_dag_and_verified_combined_merge(inventory):
    files = {"api": ("app/api_note.py", "NOTE = 'api'\n"),
             "ui": ("frontend/banner.txt", "Inventory\n"),
             "join": ("app/join_note.py", "NOTE = 'joined'\n")}
    farm = Farm(inventory, files, simultaneous=True)
    thread, base = register(farm, files, dependent=True, roles={"ui": "frontend"})
    reused = farm.worktrees.ensure_worktree(thread, "join", base)
    first = asyncio.run(farm.dispatch_ready(thread))
    assert set(first["results"]) == {"api", "ui"}
    assert all(row["status"] == "completed" for row in first["results"].values())
    assert farm.started == {"api": base, "ui": base}
    with pytest.raises(InvalidTransitionError, match="integration tickets"):
        farm.verify(thread)
    assert farm.integration_status(thread)["head_sha"] is None

    notes = reused.path / "local-notes.txt"
    notes.write_text("Uncommitted notes")
    rejected = asyncio.run(farm.dispatch_ready(thread))
    assert "dirty or divergent" in rejected["results"]["join"]["error"]
    assert notes.read_text() == "Uncommitted notes"
    assert git(reused.path, "rev-parse", "HEAD") == base
    notes.unlink()
    second = asyncio.run(farm.dispatch_ready(thread))
    assert second["results"]["join"]["status"] == "completed"
    assert farm.started["join"] != base
    report = farm.verify(thread, "api")
    assert report["passed"]
    head = report["commit_sha"]
    assert farm.status(thread)["thread"]["status"] == "WaitingDiffApproval"
    assert git(inventory, "rev-parse", f"refs/heads/thread/{thread}/integration") == head
    assert git(inventory, "rev-parse", "HEAD") == base
    proposal = farm.integration_diff(thread)
    assert proposal["head_sha"] == head
    assert all(path in proposal["diff"] for path, _ in files.values())
    checkpoint = farm.repo.get_latest_checkpoint(thread, "diff")
    assert checkpoint is not None
    review = asyncio.run(farm.goldfish_review(thread, checkpoint.id, ["codebase-alignment"]))
    assert review["reviews"][0]["status"] == "completed"
    assert review["reviews"][0]["commit_sha"] == head
    assert farm.repo.get_checkpoint(checkpoint.id).status == "pending"
    with pytest.raises(InvalidTransitionError):
        farm.merge("api", head, base)
    with pytest.raises(InvalidTransitionError):
        farm.merge_integration(thread, first["results"]["api"]["result_sha"], base)
    assert farm.merge_integration(thread, head, base)["result_sha"] == head
    assert git(inventory, "rev-parse", "HEAD") == head


def test_conflicting_parallel_changes_leave_target_and_integration_unmoved(inventory):
    files = {"api": ("app/shared.py", "VALUE = 'api'\n"),
             "ui": ("app/shared.py", "VALUE = 'ui'\n")}
    farm = Farm(inventory, files, simultaneous=True)
    thread, base = register(farm, files)
    asyncio.run(farm.dispatch_ready(thread))
    with pytest.raises(InvalidTransitionError, match="Could not integrate ticket.*app/shared.py"):
        farm.verify(thread)
    assert farm.integration_status(thread)["head_sha"] is None
    assert git(inventory, "rev-parse", "HEAD") == base
    assert farm.repo.get_latest_checkpoint(thread, "diff") is None


def test_failed_combined_verification_never_opens_approval(inventory):
    files = {"api": ("app/inventory.py", "invalid inventory source\n"),
             "ui": ("frontend/banner.txt", "Inventory\n")}
    farm = Farm(inventory, files)
    thread, base = register(farm, files, roles={"ui": "frontend"})
    asyncio.run(farm.dispatch_ready(thread))
    report = farm.verify(thread)
    assert not report["passed"]
    assert report["commit_sha"] == farm.integration_status(thread)["head_sha"]
    assert farm.status(thread)["thread"]["status"] == "Executing"
    assert farm.repo.get_latest_checkpoint(thread, "diff") is None
    assert git(inventory, "rev-parse", "HEAD") == base


def test_parallel_workers_pause_at_aggregate_credit_cap(inventory):
    path = inventory / ".thread/policy.yaml"
    policy = yaml.safe_load(path.read_text())
    policy["caps"]["max_credits_per_thread"] = 3
    path.write_text(yaml.safe_dump(policy))
    git(inventory, "add", ".thread/policy.yaml")
    git(inventory, "commit", "-qm", "Cap available credits")
    gate = asyncio.Event()
    started = []

    class Adapter(MockWorkerAdapter):
        async def start(self, assignment):
            await super().start(assignment)
            started.append(assignment.ticket_id)
            if len(started) == 2:
                gate.set()
            await asyncio.wait_for(gate.wait(), 5)

        async def stream_events(self):
            self._usage.credits_used = 1.5
            self._usage.turns_used = 1
            yield self._redact_event("usage", "Recorded one mock turn")
            await asyncio.sleep(0)
            yield self._redact_event("session_idle")

    class QuotaFarm(Workflow):
        def _adapter(self, policy):
            return Adapter(policy)

    farm = QuotaFarm(inventory)
    files = {"api": ("app/api_note.py", ""), "ui": ("app/ui_note.py", ""), "next": ("app/next_note.py", "")}
    thread, _ = register(farm, files)
    results = asyncio.run(farm.dispatch_ready(thread))
    assert len(started) == 2 and len(results["deferred"]) == 1
    assert all(result["status"] == "paused_quota" for result in results["results"].values())
    saved = farm.repo.get_thread(thread)
    assert saved.status == "PausedQuota" and saved.credits_used == 3
    assert not farm.repo.list_running_assignments(thread)
    with pytest.raises(InvalidTransitionError, match="executing thread"):
        asyncio.run(farm.dispatch_ready(thread))
