from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from thread_sdlc.context import ContextIndex

INVENTORY = Path(__file__).resolve().parents[2] / "examples" / "inventory-app"


def _git(repo: Path, *arguments: str) -> None:
    subprocess.run(["git", *arguments], cwd=repo, check=True, capture_output=True)


def _write(repo: Path, path: str, text: str) -> None:
    file = repo / path
    file.parent.mkdir(parents=True, exist_ok=True)
    file.write_text(text, encoding="utf-8")


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q")
    return root


def test_rebuild_searches_inventory_and_distinguishes_graph_provenance(repo: Path) -> None:
    shutil.copytree(INVENTORY / "app", repo / "app")
    shutil.copytree(INVENTORY / "docs", repo / "docs")
    _write(repo, "app/__init__.py", "")
    _write(repo, "app/snapshot.py", "from .inventory import create_app\n")
    _write(repo, "web/widget.ts", "export function InventoryWidget() {}\n")
    _git(repo, "add", "--", "app", "docs", "web")

    index = ContextIndex(repo)
    stats = index.rebuild()
    assert stats["files"] >= 5
    assert stats["edges"] >= 5
    assert index.db_path.is_file()

    result = index.search("create_app")
    assert result["mode"] == "lexical"
    assert "app/inventory.py" in {item["path"] for item in result["results"]}
    assert all(len(item["snippet"]) <= 500 for item in result["results"])
    assert index.search("inventory + requests (stock)!", limit=1)["results"]

    observed = index.graph(provenance="observed")
    assert {edge["provenance"] for edge in observed["edges"]} == {"observed"}
    assert any(node["kind"] == "business_rule" and node["label"] == "BR-INV-01" for node in observed["nodes"])
    assert any(edge["relation"] == "defines" and edge["path"] == "app/inventory.py" for edge in observed["edges"])
    inferred = index.graph(provenance="inferred")
    assert {edge["provenance"] for edge in inferred["edges"]} == {"inferred"}
    assert any(edge["target"] == "file:app/inventory.py" and edge["relation"] == "resolves_to"
               for edge in inferred["edges"])
    assert any(node["label"] == "InventoryWidget" for node in inferred["nodes"])
    query = index.graph("inventorywidget", limit=1)
    assert len(query["edges"]) == 1
    assert {query["edges"][0]["source"], query["edges"][0]["target"]} == {
        node["id"] for node in query["nodes"]
    }
    assert index.graph("missing symbol") == {"nodes": [], "edges": []}


def test_rebuild_skips_untracked_hidden_and_linked_files_and_redacts(repo: Path) -> None:
    outside = repo.parent / "outside"
    outside.mkdir()
    _write(outside, "member.py", "OutOfBounds = 1\n")
    _write(repo, ".hidden.py", "HiddenCode = 1\n")
    _write(repo, "candidate.py", "def safe_function():\n    return 'ghp_AnOfflineSecret00001'\n")
    _write(repo, "pkg/member.py", "OldValue = 1\n")
    (repo / "link.py").symlink_to(outside / "member.py")
    _git(repo, "add", "--", ".hidden.py", "candidate.py", "link.py", "pkg/member.py")
    shutil.rmtree(repo / "pkg")
    (repo / "pkg").symlink_to(outside, target_is_directory=True)
    _write(repo, "untracked.py", "UntrackedCode = 1\n")

    index = ContextIndex(repo)
    assert index.rebuild()["files"] == 1
    assert index.search("safe_function")["results"]
    for term in ("AnOfflineSecret00001", "OutOfBounds", "HiddenCode", "UntrackedCode"):
        assert index.search(term)["results"] == []
    assert b"AnOfflineSecret00001" not in index.db_path.read_bytes()

    _git(repo, "rm", "--cached", "--", "candidate.py")
    assert index.rebuild()["files"] == 0
    assert index.search("safe_function")["results"] == []


def test_offload_compacts_tests_and_diffs_and_fetches_redacted_chunks(repo: Path) -> None:
    index = ContextIndex(repo)
    output = "quiet lines\n" * 300 + "FAILED suite.py::test_total\n2 passed, 1 failed\n"
    offload = index.offload(output, "test")
    assert offload["compacted"]
    assert offload["preview"] == "FAILED suite.py::test_total\n2 passed, 1 failed"
    assert index.offload(output, "test")["reference"] == offload["reference"]

    patch = "diff --git a/old.py b/new.py\n--- a/old.py\n+++ b/new.py\n-old\n+new\n"
    compact = index.offload(patch, "diff")
    assert compact["preview"].startswith("1 files, +1 / -1")

    redacted = index.offload("履歴\nAuthorization: Bearer fabricated_example_value\nfin")
    recreated = ContextIndex(repo)
    first = recreated.fetch(redacted["reference"], limit=2)
    assert first["text"] == "履歴"
    assert first["next_offset"] == 2
    last = recreated.fetch(redacted["reference"], offset=first["next_offset"])
    assert "fabricated_example_value" not in last["text"]
    assert "[REDACTED]" in last["text"]
    assert last["next_offset"] is None
    assert recreated.fetch(compact["reference"])["text"] == patch
    assert recreated.fetch(offload["reference"])["text"] == output
    with pytest.raises(ValueError, match="Invalid context reference"):
        recreated.fetch("not-a-reference")
    with pytest.raises(ValueError, match="Unknown context reference"):
        recreated.fetch("context:" + "a" * 64)
    with pytest.raises(ValueError, match="one MiB"):
        recreated.offload("x" * (1024 * 1024 + 1))


def test_optional_embeddings_rank_without_literal_match_and_fall_back(repo: Path, monkeypatch) -> None:
    _write(repo, "checkout.py", "def reserve():\n    return 'allocation'\n")
    _write(repo, "list.py", "def list_items():\n    return 'inventory'\n")
    _git(repo, "add", "--", "checkout.py", "list.py")

    class TinyModel:
        def embed(self, texts: list[str]) -> list[list[float]]:
            return [[1.0, 0.0] if "hold" in item or "reserve" in item else [0.0, 1.0] for item in texts]

    index = ContextIndex(repo, embedder=TinyModel())
    index.rebuild()
    assert index.search("hold")["results"] == []
    semantic = index.search("hold", semantic=True, limit=1)
    assert semantic["mode"] == "semantic"
    assert semantic["results"][0]["path"] == "checkout.py"

    monkeypatch.setenv("THREAD_CONTEXT_MODEL_DIR", str(repo / "missing-model"))
    lexical = ContextIndex(repo).search("inventory", semantic=True)
    assert lexical["mode"] == "lexical"
    assert lexical["semantic_fallback"]
    assert lexical["results"][0]["path"] == "list.py"


def test_fastembed_adapter_supplies_only_local_model_options(repo: Path, monkeypatch) -> None:
    model_dir = repo.parent / "local-model"
    model_dir.mkdir()
    calls = []

    class StubFastEmbed:
        def __init__(self, **options):
            calls.append(options)

        def embed(self, texts, *, parallel):
            assert parallel is None
            return [SimpleNamespace(tolist=lambda: [1.0, 0.0]) for _ in texts]

    monkeypatch.setitem(sys.modules, "fastembed", SimpleNamespace(TextEmbedding=StubFastEmbed))
    monkeypatch.setenv("THREAD_CONTEXT_MODEL_DIR", str(model_dir))
    _write(repo, "check.py", "def check():\n    return 'inventory'\n")
    _git(repo, "add", "--", "check.py")

    index = ContextIndex(repo)
    index.rebuild()
    assert index.search("stock", semantic=True)["mode"] == "semantic"
    assert calls[0]["specific_model_path"] == str(model_dir)
    assert calls[0]["local_files_only"] is True


def test_context_state_rejects_linked_directory_and_database(repo: Path) -> None:
    outside = repo.parent / "outside"
    outside.mkdir()
    state = repo / ".thread-state"
    state.symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError, match="real repository directory"):
        ContextIndex(repo).graph()
    assert list(outside.iterdir()) == []

    state.unlink()
    state.mkdir()
    (state / "context.db").symlink_to(outside / "foreign.db")
    with pytest.raises(ValueError, match="regular files"):
        ContextIndex(repo).graph()
    assert list(outside.iterdir()) == []
