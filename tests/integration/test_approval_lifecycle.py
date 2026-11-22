"""Release gate for policy-owned, revision-bound approvals on real Git checkouts."""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

from fastapi.testclient import TestClient
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
import pytest

from thread_sdlc.orchestrator import engine
from thread_sdlc.orchestrator.engine import InvalidTransitionError, Workflow
from thread_sdlc.ui.api import create_app
from thread_sdlc.workers.adapter import MockWorkerAdapter


ROOT = Path(__file__).resolve().parents[2]
INVENTORY = ROOT / "examples" / "inventory-app"
ORIGIN = "http://127.0.0.1:4242"
LAUNCH_TOKEN = "inventory-release-test-token"
INVENTORY_SOURCE = Path("app/inventory.py")


def git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=root, check=True, text=True, capture_output=True, timeout=15,
    ).stdout.strip()


def commit(root: Path, message: str) -> str:
    git(root, "add", "--all")
    git(root, "commit", "--quiet", "-m", message)
    return git(root, "rev-parse", "HEAD")


@pytest.fixture
def inventory_repo(tmp_path: Path) -> Path:
    root = tmp_path / "inventory"
    shutil.copytree(
        INVENTORY, root,
        ignore=shutil.ignore_patterns(".git", ".thread-state", "__pycache__", ".pytest_cache"),
    )
    config = root / ".thread/config.yaml"
    config.write_text(
        config.read_text(encoding="utf-8").replace("adapter: auto", "adapter: mock"),
        encoding="utf-8",
    )
    git(root, "init", "--quiet", "--initial-branch=main")
    git(root, "config", "user.name", "Thread release fixture")
    git(root, "config", "user.email", "thread@example.test")
    commit(root, "Inventory fixture baseline")
    return root


@pytest.fixture
def ui(inventory_repo: Path):
    with TestClient(create_app(inventory_repo, LAUNCH_TOKEN, 4242), base_url=ORIGIN) as client:
        response = client.get("/", params={"token": LAUNCH_TOKEN}, follow_redirects=False)
        assert response.status_code == 303
        assert client.get("/api/auth/session").status_code == 200
        yield client


def next_checkpoint(workflow: Workflow, thread_id: str, stage: str) -> dict:
    return next(
        cp for cp in workflow.status(thread_id)["checkpoints"]
        if cp["stage"] == stage and cp["status"] == "pending"
    )


def decision(ui: TestClient, checkpoint: dict, **overrides):
    fields = {
        "decision": "approved",
        "content_sha256": checkpoint["content_sha256"],
        "git_head_sha": checkpoint["git_head_sha"],
    }
    return ui.post(
        f"/api/checkpoints/{checkpoint['id']}/decide",
        json={**fields, **overrides}, headers={"Origin": ORIGIN},
    )


def inventory_ticket(path: str = INVENTORY_SOURCE.as_posix()) -> dict:
    return {
        "id": "inventory-ticket", "title": "Update inventory", "role": "backend", "paths": [path],
    }


@asynccontextmanager
async def mcp_process(root: Path):
    parameters = StdioServerParameters(
        command=sys.executable,
        args=["-c", "from thread_sdlc.cli.main import app; app()", "mcp", "--repo", str(root)],
        cwd=root,
        env={"PYTHONPATH": str(ROOT / "src"), "PYTHONDONTWRITEBYTECODE": "1"},
    )
    async with stdio_client(parameters) as (reader, writer):
        async with ClientSession(reader, writer) as session:
            async with asyncio.timeout(15):
                await session.initialize()
            yield session


async def call_tool(session: ClientSession, name: str, **arguments):
    async with asyncio.timeout(15):
        result = await session.call_tool(name, arguments)
    payload = result.model_dump(by_alias=True)
    assert not payload.get("isError"), payload["content"]
    if payload.get("structuredContent") is not None:
        return payload["structuredContent"]
    return json.loads(payload["content"][0]["text"])


def test_mcp_process_restart_resumes_after_human_spec_approval(
    inventory_repo: Path, ui: TestClient,
) -> None:
    async def open_review():
        async with mcp_process(inventory_repo) as session:
            task = await call_tool(
                session, "thread_start_or_resume", request="Implement INV-101 full-stack reservations",
                artifacts=["docs/stories/INV-101.md", "contracts/openapi.yaml"],
            )
            thread_id = task["thread"]["id"]
            cp = await call_tool(
                session, "thread_save_checkpoint", thread_id=thread_id,
                stage="spec", content_md="# Inventory\nConcurrent requests must not oversell.",
            )
            assert cp["status"] == "pending"
            assert cp["waits_for_person"] is True
        return thread_id, cp

    # Closing the stdio client exits the first MCP subprocess before browser review.
    thread_id, checkpoint = asyncio.run(open_review())
    note = ui.post(
        f"/api/checkpoints/{checkpoint['id']}/annotations",
        headers={"Origin": ORIGIN},
        json={"comment": "Keep the last-unit race as an acceptance gate.", "line_or_section": "Inventory"},
    )
    assert note.status_code == 200, note.text
    assert decision(ui, checkpoint, content_sha256="0" * 64).status_code == 409
    approved = decision(ui, checkpoint)
    assert approved.status_code == 200, approved.text
    assert approved.json()["permitted_next_stage"] == "PlanDraft"

    async def resume():
        async with mcp_process(inventory_repo) as restarted:
            task = await call_tool(restarted, "thread_start_or_resume", thread_id=thread_id)
            assert task["thread"]["status"] == "PlanDraft"
            assert task["annotations"] == [note.json()]
            result = await call_tool(
                restarted, "thread_check_review", thread_id=thread_id, checkpoint_id=checkpoint["id"],
            )
            assert result["checkpoint"]["status"] == "approved"
            assert result["checkpoint"]["content_sha256"] == checkpoint["content_sha256"]
            assert result["checkpoint"]["git_head_sha"] == checkpoint["git_head_sha"]

    asyncio.run(resume())


def test_edited_checkpoints_and_base_changes_invalidate_approvals(
    inventory_repo: Path, ui: TestClient,
) -> None:
    workflow = Workflow(inventory_repo)
    thread_id = workflow.start_or_resume("Implement INV-101 full-stack reservations")["thread"]["id"]
    spec = workflow.save_checkpoint(thread_id, "spec", "Initial spec")
    assert decision(ui, spec).status_code == 200
    workflow.plan_tickets(thread_id, [inventory_ticket()])
    plan = workflow.save_checkpoint(thread_id, "plan", "Initial plan")
    assert decision(ui, plan, git_head_sha="0" * 40).status_code == 409
    assert decision(ui, plan).status_code == 200

    revised_plan = workflow.save_checkpoint(thread_id, "plan", "Revised plan")
    assert workflow.check_review(thread_id, plan["id"])["checkpoint"]["status"] == "stale"
    assert decision(ui, plan).status_code == 409
    assert decision(ui, revised_plan, content_sha256=plan["content_sha256"]).status_code == 409
    assert decision(ui, revised_plan).status_code == 200

    revised_spec = workflow.save_checkpoint(thread_id, "spec", "Revised spec")
    for checkpoint in (spec, revised_plan):
        assert workflow.check_review(thread_id, checkpoint["id"])["checkpoint"]["status"] == "stale"
    assert decision(ui, revised_spec).status_code == 200
    new_plan = workflow.save_checkpoint(thread_id, "plan", "Plan for revised spec")
    assert decision(ui, new_plan).status_code == 200

    (inventory_repo / "base-revision.txt").write_text("Another accepted base change\n", encoding="utf-8")
    new_base = commit(inventory_repo, "Move reviewed base revision")
    snapshot = workflow.status(thread_id)
    assert snapshot["thread"]["status"] == "SpecDraft"
    assert snapshot["thread"]["base_sha"] == new_base
    for checkpoint in (revised_spec, new_plan):
        assert workflow.check_review(thread_id, checkpoint["id"])["checkpoint"]["status"] == "stale"
        assert decision(ui, checkpoint).status_code == 409


@pytest.mark.parametrize("escalation", ["planned", "observed"])
def test_track_one_escalation_requires_both_spec_and_plan(
    escalation: str, inventory_repo: Path, ui: TestClient, monkeypatch: pytest.MonkeyPatch,
) -> None:
    workflow = Workflow(inventory_repo)
    task = workflow.start_or_resume("Quick fix in Inventory")
    thread_id = task["thread"]["id"]
    assert task["thread"]["track"] == 1

    contract_path = "contracts/openapi.yaml"
    if escalation == "planned":
        escalated = workflow.plan_tickets(thread_id, [inventory_ticket(contract_path)])
    else:
        workflow.plan_tickets(thread_id, [inventory_ticket()])
        contract = (inventory_repo / contract_path).read_text(encoding="utf-8")
        updated_contract = contract.replace(
            "  title: Inventory reservations\n",
            "  title: Inventory reservations\n  description: Reserve and release inventory.\n",
        )
        assert updated_contract != contract

        def contract_worker(policy):
            return MockWorkerAdapter(
                policy, allowed_file_relpath=contract_path, allowed_content=updated_contract,
            )

        monkeypatch.setattr(engine, "MockWorkerAdapter", contract_worker)
        result = asyncio.run(workflow.dispatch_worker(thread_id, "inventory-ticket", "Update inventory"))
        assert result["status"] == "completed"
        escalated = workflow.verify(thread_id)
        assert escalated["status"] == "Escalated"
        assert escalated["passed"] is False

    assert escalated["thread"]["track"] == 3
    assert escalated["thread"]["status"] == "SpecDraft"
    assert contract_path in escalated["thread"]["risk_reasons"]

    spec = workflow.save_checkpoint(thread_id, "spec", "Review the inventory API change")
    with pytest.raises(InvalidTransitionError, match="Checkpoint not allowed"):
        workflow.save_checkpoint(thread_id, "plan", "Skip spec approval")
    with pytest.raises(InvalidTransitionError, match="Dispatch requires an executing thread"):
        asyncio.run(workflow.dispatch_worker(thread_id, "inventory-ticket", "Do not skip review"))
    assert decision(ui, spec).status_code == 200
    assert workflow.status(thread_id)["thread"]["status"] == "PlanDraft"
    plan = workflow.save_checkpoint(thread_id, "plan", "Plan the inventory API change")
    with pytest.raises(InvalidTransitionError, match="Dispatch requires an executing thread"):
        asyncio.run(workflow.dispatch_worker(thread_id, "inventory-ticket", "Wait for plan approval"))
    assert decision(ui, plan).status_code == 200
    assert workflow.status(thread_id)["thread"]["status"] == "Executing"


def prepare_baseline(inventory_repo: Path, track: int) -> tuple[str, str]:
    path = inventory_repo / INVENTORY_SOURCE
    completed = path.read_text(encoding="utf-8")
    if track == 1:
        clean = "<h1>Inventory reservations</h1>"
        typo = "<h1>Inventroy reservations</h1>"
        baseline = completed.replace(clean, typo)
        assert baseline.count(typo) == 1
    else:
        start = completed.index("\n", completed.index("    def reserve("))
        end = completed.index("\n    @app.delete(", start)
        placeholder = '\n        raise HTTPException(501, "Reservations are not implemented")\n'
        baseline = completed[:start] + placeholder + completed[end:]
        assert "BEGIN IMMEDIATE" not in baseline

    path.write_text(baseline, encoding="utf-8")
    return commit(inventory_repo, f"Prepare Track {track} walkthrough baseline"), completed


@pytest.mark.parametrize("track", [1, 3], ids=["track-1-quick-fix", "track-3-inv-101"])
def test_inventory_walkthrough(
    track: int, inventory_repo: Path, ui: TestClient, monkeypatch: pytest.MonkeyPatch,
) -> None:
    base, completed = prepare_baseline(inventory_repo, track)

    def fixture_worker(policy):
        return MockWorkerAdapter(
            policy, allowed_file_relpath=INVENTORY_SOURCE.as_posix(), allowed_content=completed,
        )

    # Only the mock worker output is fixture-supplied. Worktree, scope enforcement,
    # database state, verification, revision binding and merge use real paths.
    monkeypatch.setattr(engine, "MockWorkerAdapter", fixture_worker)
    workflow = Workflow(inventory_repo)
    request, artifacts = (
        ("Fix the heading typo in inventory", [])
        if track == 1
        else ("Implement INV-101 Inventory Reservations", ["docs/stories/INV-101.md", "contracts/openapi.yaml"])
    )
    task = workflow.start_or_resume(request, artifacts=artifacts)
    assert task["thread"]["track"] == track
    thread_id = task["thread"]["id"]
    if track == 3:
        spec = workflow.save_checkpoint(
            thread_id, "spec", "BR-INV-01 prevents overselling. BR-INV-02 releases expired stock.",
        )
        assert decision(ui, spec).status_code == 200
    workflow.plan_tickets(thread_id, [inventory_ticket()])
    if track == 3:
        plan = workflow.save_checkpoint(
            thread_id, "plan", "Serialize concurrent claims and expire stale allocations.",
        )
        assert decision(ui, plan).status_code == 200
    else:
        assert workflow.status(thread_id)["checkpoints"] == []

    dispatched = asyncio.run(workflow.dispatch_worker(thread_id, "inventory-ticket", request))
    assert dispatched["worker_invoked"] is True
    assert dispatched["status"] == "completed"
    head = dispatched["result_sha"]
    assert head != base
    assert git(inventory_repo, "rev-parse", "HEAD") == base

    verified = workflow.verify(thread_id, "inventory-ticket")
    assert verified["passed"], verified["scorecard"]
    assert verified["commit_sha"] == head
    assert {item["rule_id"]: item["outcome"] for item in verified["rule_evidence"]} == {
        "BR-INV-01": "passed", "BR-INV-02": "passed",
    }
    assert all(
        item["provenance"] == "observed" and item["commit_sha"] == head
        for item in verified["rule_evidence"]
    )
    with pytest.raises(InvalidTransitionError, match="human merge receipt"):
        workflow.complete(thread_id)

    review = next_checkpoint(workflow, thread_id, "diff")
    proposal_response = ui.get("/api/tickets/inventory-ticket/diff")
    assert proposal_response.status_code == 200, proposal_response.text
    proposal = proposal_response.json()
    assert proposal["head_sha"] == review["git_head_sha"] == head
    assert proposal["base_sha"] == base
    assert review["content_md"] == proposal["diff"]
    assert review["content_sha256"] == hashlib.sha256(proposal["diff"].encode()).hexdigest()
    assert decision(ui, review).status_code == 409

    merge_path = "/api/tickets/inventory-ticket/merge"
    wrong = ui.post(
        merge_path, headers={"Origin": ORIGIN},
        json={"expected_head": base, "expected_base": base},
    )
    assert wrong.status_code == 409
    assert git(inventory_repo, "rev-parse", "HEAD") == base
    accepted = ui.post(
        merge_path, headers={"Origin": ORIGIN},
        json={"expected_head": head, "expected_base": base},
    )
    assert accepted.status_code == 200, accepted.text
    assert git(inventory_repo, "rev-parse", "HEAD") == head
    assert (inventory_repo / INVENTORY_SOURCE).read_text(encoding="utf-8") == completed
    assert workflow.check_review(thread_id, review["id"])["checkpoint"]["status"] == "approved"
    assert workflow.complete(thread_id)["thread"]["status"] == "Completed"
