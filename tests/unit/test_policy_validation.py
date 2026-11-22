"""Permission decisions using inert requests; no worker commands run."""

import asyncio
from pathlib import Path

import pytest

from thread_sdlc.workers.copilot_sdk import CopilotSdkAdapter
from thread_sdlc.workers.permissions import RolePolicy, ScopeViolationError


@pytest.fixture
def policy(tmp_path: Path) -> RolePolicy:
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "item.txt").write_text("fixture")
    return RolePolicy(
        role="backend",
        worktree_root=tmp_path,
        allowed_paths=["app/**"],
        denied_paths=["app/private/**"],
        allowed_shell_prefixes=["git"],
    )


def test_git_requires_scoped_operands(policy: RolePolicy) -> None:
    assert policy.enforce_shell("git restore app/item.txt")
    assert policy.enforce_shell("git -C app restore item.txt")
    assert policy.enforce_shell("git checkout -- app/item.txt")
    assert policy.enforce_shell("git add app/item.txt")
    assert policy.enforce_shell("git add -- app/item.txt")


@pytest.mark.parametrize("command", [
    "git restore docs/item.txt",
    "git restore app/item.txt app/private/item.txt",
    "git restore .",
    "git checkout app/item.txt",
    "git checkout docs/item.txt",
    "git checkout -- docs/item.txt",
    "git add app/item.txt docs/item.txt",
    "git add app",
    "git add .",
    "git clean -n",
    "git config --file app/settings.ini user.name Example",
    "git reset",
])
def test_git_rejects_out_of_scope_or_unsupported_mutations(policy: RolePolicy, command: str) -> None:
    with pytest.raises(ScopeViolationError):
        policy.enforce_shell(command)


def test_git_write_operands_match_the_validated_path(policy: RolePolicy) -> None:
    alias = policy.worktree_root / "alias.txt"
    alias.symlink_to("app/item.txt")
    for command in ("git add alias.txt", "git restore 'app/item.txt '"):
        with pytest.raises(ScopeViolationError):
            policy.enforce_shell(command)


def test_git_init_resolves_metadata_from_the_destination(policy: RolePolicy) -> None:
    assert policy.enforce_shell("git --git-dir=.git init app/local")
    with pytest.raises(ScopeViolationError):
        policy.enforce_shell("git --git-dir=app/local/.git init app/local")

    local = policy.worktree_root / "app" / "local"
    local.mkdir()
    (local / ".git").write_text("ordinary fixture file")
    with pytest.raises(ScopeViolationError):
        policy.enforce_shell("git init app/local")


def test_git_clone_requires_local_operands_and_rejects_options(policy: RolePolicy) -> None:
    assert policy.enforce_shell("git clone app app/dst")
    for command in (
        "git clone app docs/dst",
        "git clone --unknown-flag app app/dst",
        "git clone -qv app app/dst",
        "git clone -qu",
    ):
        with pytest.raises(ScopeViolationError):
            policy.enforce_shell(command)


def test_readonly_permits_inspection_and_denies_file_producers(policy: RolePolicy) -> None:
    reviewer = RolePolicy(
        role="reviewer_readonly",
        worktree_root=policy.worktree_root,
        allowed_shell_prefixes=["git"],
        readonly=True,
    )
    assert reviewer.enforce_shell("git status --short")
    assert reviewer.enforce_shell("git log --oneline")
    for cmd in (
        "git bundle create app/history.bundle HEAD",
        "git format-patch HEAD",
        "git archive HEAD",
        "git config user.name Jane",
        "git fast-import",
        "git filter-branch",
    ):
        with pytest.raises(ScopeViolationError):
            reviewer.enforce_shell(cmd)


def test_hybrid_tool_validates_both_operations(policy: RolePolicy) -> None:
    with pytest.raises(ScopeViolationError):
        policy.enforce_tool_call("create_script", {"path": "app/item.txt"})
    policy.enforce_tool_call("create_script", {"path": "app/item.txt", "command": "git status"})


@pytest.mark.parametrize("key", ["params", "parameters"])
def test_sdk_argument_aliases(policy: RolePolicy, key: str) -> None:
    adapter = CopilotSdkAdapter(policy)
    for target, allowed in (("app/item.txt", True), ("docs/item.txt", False)):
        result = asyncio.run(adapter._on_permission_request({
            "kind": "mcp", "toolName": "write_file", key: {"path": target}
        }))
        assert (result["kind"] == "approved") == allowed


@pytest.mark.parametrize("key", ["targetFile", "target_file", "targetFilePath"])
def test_sdk_validates_each_write_target(policy: RolePolicy, key: str) -> None:
    adapter = CopilotSdkAdapter(policy)
    result = asyncio.run(adapter._on_permission_request({
        "kind": "write", "path": "app/item.txt", key: "docs/item.txt",
    }))
    assert result["kind"] == "denied-by-rules"
