import asyncio
import json
import subprocess

import pytest
import yaml

from thread_sdlc.compiler.engine import apply
from thread_sdlc.orchestrator.engine import InvalidTransitionError, Workflow
from thread_sdlc.workers.adapter import MockWorkerAdapter
from thread_sdlc.workers.permissions import ScopeViolationError


@pytest.fixture
def draft(tmp_path):
    repo = tmp_path / "inventory"
    repo.mkdir()

    def git(*args):
        return subprocess.check_output(["git", *args], cwd=repo, text=True).strip()

    git("init", "-q", "-b", "main")
    git("config", "user.name", "Thread Test")
    git("config", "user.email", "test@example.test")
    (repo / "README.md").write_text("Committed inventory documentation\n")
    (repo / ".gitignore").write_text(".thread-state/\n")
    apply(repo, initialize=True)
    config_path = repo / ".thread/config.yaml"
    config = yaml.safe_load(config_path.read_text())
    config.update(adapter="mock", features={"m3b": True})
    config_path.write_text(yaml.safe_dump(config))
    (repo / ".thread/constitution.md").write_text("Inventory scope is reviewed against the actual API.\n")
    git("add", ".")
    git("commit", "-qm", "Inventory")
    workflow = Workflow(repo)
    thread = workflow.start_or_resume("Implement inventory reservations", ["contracts/openapi.yaml"])["thread"]
    checkpoint = workflow.save_checkpoint(thread["id"], "spec", "Compare inventory against the published contract.")
    return workflow, thread, checkpoint


def test_fresh_read_only_profiles_use_pinned_artifacts_and_persist_redacted_findings(draft, monkeypatch):
    workflow, thread, checkpoint = draft
    (workflow.root / "README.md").write_text("Uncommitted documentation\n")
    (workflow.root / ".thread/constitution.md").write_text("Uncommitted constitution\n")
    created = []

    class Reviewer(MockWorkerAdapter):
        async def start(self, assignment):
            assert self.start_count == 0
            assert self._policy.role == "reviewer_readonly"
            assert self._policy.readonly and self._policy.allowed_shell_prefixes == []
            with pytest.raises(ScopeViolationError):
                self._policy.enforce_write("README.md")
            with pytest.raises(ScopeViolationError):
                self._policy.enforce_read(str(workflow.root / "README.md"))
            path = assignment.worktree_path
            assert (path / "README.md").read_text() == "Committed inventory documentation\n"
            assert assignment.base_sha == checkpoint["git_head_sha"]
            assert "Inventory scope is reviewed against the actual API." in assignment.instructions
            assert "Uncommitted constitution" not in assignment.instructions
            assert checkpoint["content_md"] in assignment.instructions
            await super().start(assignment)

        async def stream_events(self):
            yield self._redact_event(
                "assistant_message",
                json.dumps({"findings": [{"severity": "warning", "summary": "Authorization: Bearer mock_bearer_token_0123456789",
                                          "path": "README.md", "line": 1}]}),
            )

    def create(policy):
        adapter = Reviewer(policy)
        created.append(adapter)
        return adapter

    monkeypatch.setattr(workflow, "_review_adapter", create)
    result = asyncio.run(workflow.goldfish_review(thread["id"], checkpoint["id"]))
    assert [review["profile"] for review in result["reviews"]] == [
        "codebase-alignment", "design-and-risk", "implementation-readiness",
    ]
    assert all(review["status"] == "completed" for review in result["reviews"]), result
    assert len(created) == 3 and all(adapter.start_count == 1 for adapter in created)
    assert all(adapter._disconnected for adapter in created)
    assert len({adapter._assignment.worktree_path for adapter in created}) == 3
    assert all(not adapter._assignment.worktree_path.exists() for adapter in created)
    restarted = Workflow(workflow.root)
    annotations = restarted.check_review(thread["id"], checkpoint["id"])["annotations"]
    assert len(annotations) == 3
    assert all(note["target_type"] == "goldfish" and note["file_path"] == "README.md" for note in annotations)
    assert all("mock_bearer_token" not in note["comment"] for note in annotations)
    assert all("mock_bearer_token" not in event.payload_json for event in restarted.events.list_events(thread["id"]))
    with pytest.raises(InvalidTransitionError, match="cap reached"):
        asyncio.run(restarted.goldfish_review(thread["id"], checkpoint["id"], ["codebase-alignment"]))


def test_goldfish_failure_never_records_unverified_findings(draft, monkeypatch):
    workflow, thread, checkpoint = draft

    class Reviewer(MockWorkerAdapter):
        async def stream_events(self):
            yield self._redact_event("assistant_message", '{"findings":[{"summary":"missing severity"}]}')

    monkeypatch.setattr(workflow, "_review_adapter", Reviewer)
    with pytest.raises(InvalidTransitionError, match="distinct supported"):
        asyncio.run(workflow.goldfish_review(thread["id"], checkpoint["id"], ["unknown"]))
    result = asyncio.run(workflow.goldfish_review(thread["id"], checkpoint["id"], ["design-and-risk"]))
    assert result["reviews"][0]["status"] == "failed"
    assert workflow.check_review(thread["id"], checkpoint["id"])["annotations"] == []
    assert [event.type for event in workflow.events.list_events(thread["id"])[-2:]] == [
        "goldfish_started", "goldfish_failed",
    ]


def test_default_mock_reviewer_and_live_flag_reload(draft):
    workflow, thread, checkpoint = draft
    result = asyncio.run(workflow.goldfish_review(thread["id"], checkpoint["id"], ["design-and-risk"]))
    assert result["reviews"][0]["status"] == "completed"
    assert result["reviews"][0]["findings"] == []
    assert workflow.repo.get_thread(thread["id"]).credits_used == 1

    config_path = workflow.root / ".thread/config.yaml"
    config = yaml.safe_load(config_path.read_text())
    config["features"]["m3b"] = False
    config_path.write_text(yaml.safe_dump(config))
    with pytest.raises(InvalidTransitionError, match="disabled"):
        asyncio.run(workflow.goldfish_review(thread["id"], checkpoint["id"]))
