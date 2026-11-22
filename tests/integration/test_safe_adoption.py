"""Ensure adoption preserves repository-owned instructions and MCP settings."""

import json
from pathlib import Path
import shutil

import pytest
from typer.testing import CliRunner

from thread_sdlc.cli.main import app
from thread_sdlc.compiler.engine import END, START


def _snapshot(repo: Path) -> dict[Path, bytes]:
    return {path.relative_to(repo): path.read_bytes() for path in repo.rglob("*") if path.is_file()}


@pytest.fixture
def inventory_copy(tmp_path: Path) -> Path:
    example = Path(__file__).resolve().parents[2] / "examples/inventory-app"
    return shutil.copytree(
        example,
        tmp_path / "inventory",
        ignore=shutil.ignore_patterns(".git", "__pycache__", ".pytest_cache", ".thread-state"),
    )


def test_adoption_preserves_inventory_instructions_outside_managed_sections(inventory_copy: Path) -> None:
    repo = inventory_copy
    owners = repo / "CODEOWNERS"
    owners.write_text("* @fixture-owner\n")
    before = _snapshot(repo)
    args = ["init", "--repo", str(repo)]
    runner = CliRunner()
    preview = runner.invoke(app, [*args, "--dry-run"])
    assert preview.exit_code == 0, preview.output
    assert "thread.agent.md" in preview.output
    assert _snapshot(repo) == before

    adopted = runner.invoke(app, args)
    assert adopted.exit_code == 0, adopted.output
    for name in ("AGENTS.md", ".github/copilot-instructions.md"):
        path = Path(name)
        original = before[path]
        current = (repo / path).read_bytes()
        prefix, block = current.split(START.encode())
        _, suffix = block.split(END.encode())
        assert prefix == original + (b"" if original.endswith(b"\n") else b"\n")
        assert suffix in (b"\n", b"\r\n")

    config_path = Path(".vscode/mcp.json")
    old_config = before[config_path]
    new_config = (repo / config_path).read_bytes()
    previous_members = json.loads(old_config)["servers"]
    current_members = json.loads(new_config)["servers"]
    assert current_members.pop("thread")["command"] == "thread"
    assert current_members == previous_members
    # Only the new member and its separator were inserted into the original bytes.
    start = new_config.index(b', "thread": ')
    _, count = json.JSONDecoder().raw_decode(new_config[start + len(b', "thread": '):].decode())
    end = start + len(b', "thread": ') + count
    assert new_config[:start] + new_config[end:] == old_config
    assert owners.read_bytes() == before[Path("CODEOWNERS")]
    assert not (repo / ".github/CODEOWNERS").exists()

    after = _snapshot(repo)
    checked = runner.invoke(app, ["compile", "--check", "--repo", str(repo)])
    assert checked.exit_code == 0, checked.output
    assert _snapshot(repo) == after
    assert runner.invoke(app, args).exit_code == 0
    assert _snapshot(repo) == after


def test_compile_changes_only_the_existing_managed_values(inventory_copy: Path) -> None:
    repo = inventory_copy
    instructions = repo / "AGENTS.md"
    old = b"Team prefix\r\n" + START.encode() + b"\r\nOld\r\n" + END.encode() + b"\r\nTeam suffix"
    instructions.write_bytes(old)
    config = repo / ".vscode/mcp.json"
    prefix = b'{\r\n "servers": {"owned": { "command": "local" }, "thread" : '
    suffix = b' },\r\n "inputs": [] \r\n}\r\n'
    config.write_bytes(prefix + b'{"command":"outdated"}' + suffix)

    result = CliRunner().invoke(app, ["init", "--repo", str(repo)])
    assert result.exit_code == 0, result.output
    new = instructions.read_bytes()
    assert new.split(START.encode())[0] == old.split(START.encode())[0]
    assert new.split(END.encode())[1] == old.split(END.encode())[1]
    current_config = config.read_bytes()
    assert current_config.startswith(prefix) and current_config.endswith(suffix)
    assert json.loads(current_config)["servers"]["thread"]["command"] == "thread"
