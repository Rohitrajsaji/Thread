"""Exercise the authenticated Mission Control routes against the inventory repository."""

import shutil
import subprocess
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from thread_sdlc.config.loader import load_scope_config, load_thread_config
from thread_sdlc.context import ContextIndex
from thread_sdlc.orchestrator.engine import Workflow
from thread_sdlc.state import EventLogger, StateDatabase
from thread_sdlc.ui.api import create_app


ORIGIN = "http://127.0.0.1:4242"
AUTH = {"Authorization": "Bearer fixture-token"}
WRITE = {**AUTH, "Origin": ORIGIN}
STUDIO = "/api/mission-control"
FIXTURE = Path(__file__).resolve().parents[2] / "examples/inventory-app"


def git(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=repo, text=True).strip()


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    target = tmp_path / "inventory"
    shutil.copytree(FIXTURE, target, ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache"))
    git(target, "init", "-q", "-b", "main")
    git(target, "config", "user.name", "Mission Control fixture")
    git(target, "config", "user.email", "studio@example.test")
    git(target, "add", ".")
    git(target, "commit", "-qm", "Initialize inventory fixture")
    return target


def enable(repo: Path, *, graph: bool = False) -> None:
    path = repo / ".thread/config.yaml"
    config = yaml.safe_load(path.read_text())
    config["features"] = {"m3d": True, "m3c": graph}
    path.write_text(yaml.safe_dump(config))


def test_mission_control_is_authenticated_and_each_feature_is_gated(repo: Path) -> None:
    with TestClient(create_app(repo, "fixture-token", 4242), base_url=ORIGIN) as client:
        assert client.get(STUDIO).status_code == 401
        assert client.get(STUDIO, headers=AUTH).json()["enabled"] is False
        assert client.get(f"{STUDIO}/graph", headers=AUTH).status_code == 404
        assert client.get(f"{STUDIO}/config/policy", headers=AUTH).status_code == 404
        assert client.post(
            f"{STUDIO}/observations/1/promote", headers=WRITE, json={"confirm": True},
        ).status_code == 404
        enable(repo)
        assert client.get(STUDIO, headers=AUTH).json() == {"enabled": True, "graph_enabled": False}
        assert client.get(f"{STUDIO}/graph", headers=AUTH).status_code == 404


def test_graph_filters_observed_relationships_in_auth_session(repo: Path) -> None:
    enable(repo, graph=True)
    ContextIndex(repo).rebuild()
    with TestClient(create_app(repo, "fixture-token", 4242), base_url=ORIGIN) as client:
        launch = client.get("/", params={"token": "fixture-token"}, follow_redirects=False)
        assert launch.status_code == 303
        status = client.get(STUDIO)
        assert status.json() == {"enabled": True, "graph_enabled": True}
        response = client.get(f"{STUDIO}/graph", params={"provenance": "observed"})
        assert response.status_code == 200, response.text
        graph = response.json()
        assert graph["nodes"] and graph["edges"]
        nodes = {node["id"] for node in graph["nodes"]}
        for edge in graph["edges"]:
            assert edge["provenance"] == "observed"
            assert {edge["source"], edge["target"]} <= nodes


def test_memory_promotion_requires_confirmation_and_preserves_redacted_evidence(repo: Path) -> None:
    enable(repo)
    event = EventLogger(StateDatabase(repo_root=repo)).emit(
        None, "observation", {"reason": "Review the last-unit race", "api_key": "synthetic-fixture-key"},
    )
    with TestClient(create_app(repo, "fixture-token", 4242), base_url=ORIGIN) as client:
        endpoint = f"{STUDIO}/observations/{event.id}/promote"
        assert client.post(endpoint, headers={**AUTH, "Origin": "https://example.test"},
                           json={"confirm": True}).status_code == 403
        refused = client.post(endpoint, headers=WRITE, json={"confirm": False})
        assert refused.status_code in {409, 422}
        assert not (repo / ".thread/decisions").exists()

        response = client.post(endpoint, headers=WRITE, json={"confirm": True})
        assert response.status_code == 200, response.text
        decision = repo / response.json()["path"]
        assert decision.is_relative_to(repo / ".thread/decisions")
        text = decision.read_text()
        assert "Review the last-unit race" in text
        assert "synthetic-fixture-key" not in text
        again = client.post(endpoint, headers=WRITE, json={"confirm": True})
        assert again.json()["path"] == response.json()["path"]
        assert again.json()["reused"] is True
        observations = client.get(f"{STUDIO}/observations", headers=AUTH).json()["observations"]
        assert next(item for item in observations if item["id"] == event.id)["promoted_path"] == response.json()["path"]
    assert response.json()["path"] in git(repo, "status", "--short", "--untracked-files=all", "--", ".thread/decisions")


def test_policy_studio_rejects_invalid_or_stale_edits_and_invalidates_approvals(repo: Path) -> None:
    enable(repo)
    workflow = Workflow(repo)
    task = workflow.start_or_resume("Implement the inventory OpenAPI contract")["thread"]
    spec = workflow.save_checkpoint(task["id"], "spec", "# Inventory specification")
    workflow.decide(spec["id"], "approved", spec["content_sha256"], spec["git_head_sha"])
    workflow.plan_tickets(task["id"], [
        {"id": "inventory", "title": "Inventory API", "role": "backend", "paths": ["app/inventory.py"]},
    ])
    plan = workflow.save_checkpoint(task["id"], "plan", "# Inventory plan")
    workflow.decide(plan["id"], "approved", plan["content_sha256"], plan["git_head_sha"])

    with TestClient(create_app(repo, "fixture-token", 4242), base_url=ORIGIN) as client:
        endpoint = f"{STUDIO}/config/policy"
        current = client.get(endpoint, headers=AUTH).json()
        raw = (repo / ".thread/policy.yaml").read_bytes()
        rejected = client.post(endpoint, headers=WRITE, json={
            "yaml": "caps: [unexpected value", "expected_revision": current["revision"],
        })
        assert rejected.status_code in {409, 422}
        assert (repo / ".thread/policy.yaml").read_bytes() == raw

        new_policy = yaml.safe_load(current["yaml"])
        new_policy["caps"]["max_turns_per_assignment"] = 1
        update = {"yaml": yaml.safe_dump(new_policy), "expected_revision": current["revision"]}
        accepted = client.post(endpoint, headers=WRITE, json=update)
        assert accepted.status_code == 200, accepted.text
        assert accepted.json()["staled_checkpoints"] == 2
        assert client.post(endpoint, headers=WRITE, json=update).status_code == 409
    assert Workflow(repo).bundle.policy.caps.max_turns_per_assignment == 1
    state = Workflow(repo).status(task["id"])
    assert state["thread"]["status"] == "SpecDraft"
    assert {checkpoint["status"] for checkpoint in state["checkpoints"]} == {"stale"}


def test_studio_edits_config_and_scope_and_blocks_mutation_during_verification(repo: Path) -> None:
    enable(repo)
    with TestClient(create_app(repo, "fixture-token", 4242), base_url=ORIGIN) as client:
        config_endpoint = f"{STUDIO}/config/config"
        config = client.get(config_endpoint, headers=AUTH).json()
        changed_config = yaml.safe_load(config["yaml"])
        changed_config["project_name"] = "Inventory fixture renamed"
        response = client.post(config_endpoint, headers=WRITE, json={
            "yaml": yaml.safe_dump(changed_config), "expected_revision": config["revision"],
        })
        assert response.status_code == 200, response.text
        assert load_thread_config(repo).project_name == changed_config["project_name"]

        scope_endpoint = f"{STUDIO}/config/scope"
        scope = client.get(scope_endpoint, headers=AUTH).json()
        changed_scope = yaml.safe_load(scope["yaml"])
        changed_scope["roles"]["backend"]["denied_paths"].append("app/internal/**")
        change = {"yaml": yaml.safe_dump(changed_scope), "expected_revision": scope["revision"]}

        workflow = Workflow(repo)
        task = workflow.start_or_resume("Fix a spelling typo")["thread"]
        workflow.repo.update_thread(task["id"], status="Verifying")
        denied = client.post(scope_endpoint, headers=WRITE, json=change)
        assert denied.status_code == 409
        assert "app/internal/**" not in load_scope_config(repo).roles["backend"].denied_paths
        workflow.repo.update_thread(task["id"], status="Executing")

        response = client.post(scope_endpoint, headers=WRITE, json=change)
        assert response.status_code == 200, response.text
        assert "app/internal/**" in load_scope_config(repo).roles["backend"].denied_paths
