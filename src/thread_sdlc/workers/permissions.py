"""Fail-closed RolePolicy enforcement, Python 3.11 glob matching, and Copilot CLI preToolUse hook."""

from __future__ import annotations

import fnmatch
import json
import os
import shlex
import sys
from pathlib import Path, PurePosixPath
from typing import Any, Literal
from urllib.parse import urlsplit
from urllib.request import url2pathname

from thread_sdlc.config.models import RoleScope, ScopeConfig

_WRITE_TOOLS = frozenset(
    {
        "write",
        "write_file",
        "write_to_file",
        "edit",
        "edit_file",
        "create",
        "create_file",
        "fs_create",
        "delete",
        "delete_file",
        "remove",
        "remove_file",
        "unlink",
        "unlink_file",
        "move",
        "move_file",
        "rename",
        "rename_file",
        "copy",
        "copy_file",
        "patch",
        "apply_patch",
        "replace_file_content",
        "multi_replace_file_content",
        "str_replace_editor",
        "insert_edit_into_file",
        "save_file",
        "file_save",
        "rm",
        "mv",
        "cp",
        "mkdir",
        "rmdir",
        "touch",
        "truncate",
    }
)

_SHELL_TOOLS = frozenset(
    {
        "bash",
        "shell",
        "run_command",
        "execute",
        "terminal",
        "powershell",
        "cmd",
        "sh",
        "zsh",
    }
)

_READ_TOOLS = frozenset(
    {
        "read",
        "read_file",
        "view",
        "view_file",
        "grep",
        "glob",
        "find",
        "list_dir",
        "ls",
        "search",
    }
)

_ALWAYS_PROTECTED_PREFIXES = (".git", ".thread-state")

_FORBIDDEN_GIT_SUBCOMMANDS = frozenset({"merge", "push", "rebase", "worktree", "cherry-pick"})

_READONLY_MUTATING_CMDS = frozenset(
    {
        "rm",
        "mv",
        "cp",
        "touch",
        "mkdir",
        "rmdir",
        "chmod",
        "chown",
        "tee",
        "dd",
        "ln",
        "truncate",
        "install",
        "mktemp",
    }
)

_READONLY_MUTATING_GIT_SUBCOMMANDS = frozenset(
    {
        "add",
        "commit",
        "checkout",
        "switch",
        "reset",
        "clean",
        "restore",
        "merge",
        "rebase",
        "cherry-pick",
        "push",
        "pull",
        "fetch",
        "branch",
        "tag",
        "worktree",
        "stash",
        "am",
        "apply",
    }
)

_PATH_ARG_KEYS = (
    "path",
    "file_path",
    "filePath",
    "target_path",
    "targetPath",
    "target_file",
    "TargetFile",
    "target",
    "link",
    "link_path",
    "linkPath",
    "output",
    "output_path",
    "outputPath",
    "outputFile",
    "junitxml",
    "log_file",
    "logFile",
    "basetemp",
    "filename",
    "file",
    "file_name",
    "resolved_path",
    "resolvedPath",
    "destination",
    "dest",
    "dst",
    "source",
    "src",
    "old_path",
    "oldPath",
    "new_path",
    "newPath",
    "directory",
    "dir",
    "uri",
    "url",
)

_PATH_LIST_KEYS = frozenset(
    {
        "paths",
        "files",
        "file_paths",
        "filePaths",
        "targets",
        "roots",
        "directories",
        "dirs",
        "urls",
        "uris",
    }
)

_PYTEST_VALUE_SHORT_FLAGS = frozenset({"k", "m", "c", "r", "W", "n", "p"})

_READ_EXTRA_PATH_KEYS = frozenset(
    {
        "cwd",
        "working_directory",
        "workingDirectory",
        "search_path",
        "SearchPath",
        "search_paths",
        "searchPaths",
        "root",
        "root_dir",
        "rootDir",
        "folder",
        "folders",
    }
)

_COVERAGE_OUTPUT_FLAGS = frozenset({"-d", "--directory", "-o", "--output", "--data-file"})

_RUFF_VALUE_FLAGS = frozenset(
    {
        "--config",
        "--select",
        "--extend-select",
        "--ignore",
        "--extend-ignore",
        "--fixable",
        "--unfixable",
        "--extend-fixable",
        "--exclude",
        "--extend-exclude",
        "--per-file-ignores",
        "--extend-per-file-ignores",
        "--target-version",
        "--line-length",
        "--output-format",
        "--output-file",
        "-o",
        "--cache-dir",
        "--stdin-filename",
        "--extension",
    }
)

_FILE_WRITING_FLAGS = frozenset(
    {
        "--output",
        "--output-file",
        "--log-file",
        "--junitxml",
        "--junit-xml",
        "--basetemp",
        "--resultlog",
        "--result-log",
        "--cache-dir",
    }
)

_ALLOWED_PYTHON_MODULES = frozenset(
    {"pytest", "unittest", "py_compile", "compileall", "ruff", "mypy", "coverage"}
)

_SHELL_CMD_KEYS = ("command", "cmd", "script", "CommandLine", "full_command_text")


class ScopeViolationError(Exception):
    """Raised when a worker attempts an out-of-scope file or shell operation."""

    def __init__(
        self,
        role: str,
        operation: Literal["write", "shell", "tool", "read"],
        target: str,
        reason: str,
    ) -> None:
        self.role = role
        self.operation = operation
        self.target = target
        self.reason = reason
        super().__init__(f"[{role}] {operation} denied for {target!r}: {reason}")


def _normalize_pattern(pattern: str) -> list[str]:
    norm = pattern.strip().replace("\\", "/")
    while norm.startswith("./"):
        norm = norm[2:]
    norm = norm.lstrip("/")
    if norm.endswith("/"):
        norm = f"{norm}**"
    if not norm:
        return []
    return [part for part in PurePosixPath(norm).parts if part not in ("", ".")]


def _match_parts(path_parts: tuple[str, ...], pat_parts: list[str]) -> bool:
    pi, qi = 0, 0
    memo: dict[tuple[int, int], bool] = {}

    def _dp(i: int, j: int) -> bool:
        key = (i, j)
        if key in memo:
            return memo[key]
        if j == len(pat_parts):
            res = i == len(path_parts)
        elif pat_parts[j] == "**":
            # '**' matches 0 segments or >=1 segments
            res = _dp(i, j + 1) or (i < len(path_parts) and _dp(i + 1, j))
        elif i < len(path_parts) and fnmatch.fnmatchcase(path_parts[i], pat_parts[j]):
            res = _dp(i + 1, j + 1)
        else:
            res = False
        memo[key] = res
        return res

    return _dp(pi, qi)


def glob_match(rel_posix: str, pattern: str) -> bool:
    """Python 3.11-compatible recursive glob matcher supporting ``**``, ``*``, and ``?``."""
    clean_path = rel_posix.strip().replace("\\", "/").lstrip("/")
    while clean_path.startswith("./"):
        clean_path = clean_path[2:]
    if not clean_path:
        return False
    pat_parts = _normalize_pattern(pattern)
    if not pat_parts:
        return False
    path_parts = tuple(p for p in PurePosixPath(clean_path).parts if p not in ("", "."))
    return _match_parts(path_parts, pat_parts)


def _pattern_can_match_under_dir(dir_parts: tuple[str, ...], pat_parts: list[str]) -> bool:
    """Return True if ``pat_parts`` can match any descendant ``dir_parts + suffix`` (len(suffix) >= 1)."""
    if not dir_parts or not pat_parts:
        return False
    memo: dict[tuple[int, int], bool] = {}

    def _dp(i: int, j: int) -> bool:
        key = (i, j)
        if key in memo:
            return memo[key]
        if i == len(dir_parts):
            res = j < len(pat_parts)
        elif j == len(pat_parts):
            res = False
        elif pat_parts[j] == "**":
            res = _dp(i, j + 1) or _dp(i + 1, j)
        elif fnmatch.fnmatchcase(dir_parts[i], pat_parts[j]):
            res = _dp(i + 1, j + 1)
        else:
            res = False
        memo[key] = res
        return res

    return _dp(0, 0)


def _parse_bundled_pytest_o(tok: str) -> tuple[bool, str | None, bool]:
    """Inspect a short pytest option cluster like ``-qo`` or ``-qolog_file=...``.

    Returns ``(found_o, attached_val_or_none, has_empty_equals)``.
    Stops scanning at value-taking short options (``k, m, c, r, W, n, p``) so
    expressions like ``-kfoo`` or ``-mnot_slow`` are never mistaken for ``-o``.
    """
    if not tok.startswith("-") or tok.startswith("--") or len(tok) <= 2:
        return False, None, False
    chars = tok[1:]
    for j, ch in enumerate(chars):
        if ch in _PYTEST_VALUE_SHORT_FLAGS:
            return False, None, False
        if ch == "o":
            rest = chars[j + 1 :]
            if not rest:
                return True, None, False
            if rest.startswith("="):
                val = rest[1:]
                return True, val, (val == "")
            return True, rest, False
    return False, None, False


def _has_pytest_c_flag(tok: str) -> bool:
    """Return True if ``tok`` is a pytest short option cluster invoking ``-c`` (config file)."""
    if not tok.startswith("-") or tok.startswith("--") or len(tok) < 2:
        return False
    for ch in tok[1:]:
        if ch == "c":
            return True
        if ch in _PYTEST_VALUE_SHORT_FLAGS or ch == "o":
            return False
    return False


def _has_unquoted_shell_metachar(command: str) -> str | None:
    in_single = False
    in_double = False
    escaped = False
    i = 0
    n = len(command)
    while i < n:
        ch = command[i]
        if escaped:
            escaped = False
            i += 1
            continue
        if ch == "\\" and not in_single:
            escaped = True
            i += 1
            continue
        if ch == "'" and not in_double:
            in_single = not in_single
            i += 1
            continue
        if ch == '"' and not in_single:
            in_double = not in_double
            i += 1
            continue

        if in_double and (ch == "`" or (ch == "$" and i + 1 < n and command[i + 1] == "(")):
            return "$(" if ch == "$" else "`"

        if not in_single and not in_double:
            if ch in (";", "|", "`", ">", "<", "\n", "\r", "&"):
                return ch
            if ch == "$" and i + 1 < n and command[i + 1] == "(":
                return "$("
        i += 1
    return None


def _extract_patch_paths(patch_text: str) -> list[str]:
    paths: list[str] = []
    for raw_line in patch_text.splitlines():
        line = raw_line.strip()
        lower = line.lower()
        for prefix in ("+++ b/", "--- a/", "+++ ", "--- "):
            if line.startswith(prefix):
                candidate = line[len(prefix) :].split("\t", 1)[0].strip()
                if len(candidate) >= 2 and candidate.startswith('"') and candidate.endswith('"'):
                    candidate = candidate[1:-1]
                if candidate and candidate != "/dev/null":
                    paths.append(candidate)
                break
        for marker in (
            "*** update file:",
            "*** add file:",
            "*** delete file:",
            "*** move to:",
        ):
            if lower.startswith(marker):
                candidate = line[len(marker) :].strip()
                if candidate:
                    paths.append(candidate)
                break
        for git_marker in ("rename from ", "rename to ", "copy from ", "copy to "):
            if line.startswith(git_marker):
                candidate = line[len(git_marker) :].strip()
                if len(candidate) >= 2 and candidate.startswith('"') and candidate.endswith('"'):
                    candidate = candidate[1:-1]
                if candidate:
                    paths.append(candidate)
                break
    return paths


class RolePolicy:
    """Enforces role-based filesystem and shell permissions inside a worktree."""

    def __init__(
        self,
        *,
        role: str,
        worktree_root: Path,
        allowed_paths: list[str] | None = None,
        denied_paths: list[str] | None = None,
        deny_gate_files: list[str] | None = None,
        allowed_shell_prefixes: list[str] | None = None,
        readonly: bool = False,
    ) -> None:
        self.role = role
        self.worktree_root = Path(worktree_root).resolve(strict=False)
        self.allowed_paths = list(allowed_paths or [])
        self.denied_paths = list(denied_paths or [])
        self.deny_gate_files = list(deny_gate_files or [])
        self.allowed_shell_prefixes = list(allowed_shell_prefixes or [])
        self.readonly = bool(readonly)

    @classmethod
    def from_scope_config(
        cls,
        role: str,
        scope_config: ScopeConfig,
        worktree_root: Path,
    ) -> RolePolicy:
        """Construct ``RolePolicy`` from a validated ``ScopeConfig``."""
        role_scope: RoleScope | None = scope_config.roles.get(role)
        if role_scope is None:
            raise KeyError(f"Role {role!r} is not defined in ScopeConfig")
        return cls(
            role=role,
            worktree_root=worktree_root,
            allowed_paths=role_scope.allowed_paths,
            denied_paths=role_scope.denied_paths,
            deny_gate_files=scope_config.deny_gate_files,
            allowed_shell_prefixes=role_scope.allowed_shell_prefixes,
            readonly=role_scope.readonly,
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize policy for passing to `preToolUse` subprocess hooks."""
        return {
            "role": self.role,
            "worktree_root": str(self.worktree_root),
            "allowed_paths": self.allowed_paths,
            "denied_paths": self.denied_paths,
            "deny_gate_files": self.deny_gate_files,
            "allowed_shell_prefixes": self.allowed_shell_prefixes,
            "readonly": self.readonly,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RolePolicy:
        """Rehydrate ``RolePolicy`` from serialized JSON dict."""
        return cls(
            role=str(data["role"]),
            worktree_root=Path(data["worktree_root"]),
            allowed_paths=list(data.get("allowed_paths", [])),
            denied_paths=list(data.get("denied_paths", [])),
            deny_gate_files=list(data.get("deny_gate_files", [])),
            allowed_shell_prefixes=list(data.get("allowed_shell_prefixes", [])),
            readonly=bool(data.get("readonly", False)),
        )

    def _resolve_and_check_containment(
        self, target_path: str | Path, operation: Literal["write", "read"]
    ) -> tuple[Path, str]:
        orig_raw = str(target_path).strip()
        raw = orig_raw
        if not raw:
            raise ScopeViolationError(self.role, operation, orig_raw, "Empty target path")
        if "\x00" in raw:
            raise ScopeViolationError(self.role, operation, orig_raw, "Null byte in target path")
        if "://" in raw or raw.lower().startswith("file:"):
            parsed = urlsplit(raw)
            if parsed.scheme.lower() != "file":
                raise ScopeViolationError(
                    self.role, operation, orig_raw, "URI paths are not permitted"
                )
            if parsed.netloc and parsed.netloc.lower() != "localhost":
                raise ScopeViolationError(
                    self.role, operation, orig_raw, "Remote file URI hosts are not permitted"
                )
            if parsed.query or parsed.fragment:
                raise ScopeViolationError(
                    self.role,
                    operation,
                    orig_raw,
                    "File URI query or fragment components are not permitted",
                )
            raw = url2pathname(parsed.path)
            if not raw:
                raise ScopeViolationError(
                    self.role, operation, orig_raw, "Empty file URI path"
                )
            if "\x00" in raw:
                raise ScopeViolationError(
                    self.role, operation, orig_raw, "Null byte in target path"
                )

        p = Path(raw)
        candidate = p if p.is_absolute() else (self.worktree_root / p)

        # Reject symlink components whose resolved target leaves worktree_root
        probe = candidate
        while True:
            if probe.is_symlink():
                try:
                    probe.resolve(strict=False).relative_to(self.worktree_root)
                except ValueError as exc:
                    raise ScopeViolationError(
                        self.role,
                        operation,
                        orig_raw,
                        "Symlink escapes worktree root",
                    ) from exc
            if (
                probe == self.worktree_root
                or probe.resolve(strict=False) == self.worktree_root
                or probe.parent == probe
            ):
                break
            probe = probe.parent

        resolved = candidate.resolve(strict=False)
        try:
            rel = resolved.relative_to(self.worktree_root)
        except ValueError as exc:
            raise ScopeViolationError(
                self.role, operation, orig_raw, "Path escapes worktree root"
            ) from exc

        rel_posix = rel.as_posix()
        return resolved, rel_posix

    def enforce_write(self, target_path: str | Path) -> Path:
        """Verify ``target_path`` may be written by this role before touching disk."""
        raw = str(target_path)
        if self.readonly:
            raise ScopeViolationError(
                self.role, "write", raw, "Read-only role cannot write or modify files"
            )

        resolved, rel_posix = self._resolve_and_check_containment(target_path, "write")
        if rel_posix == ".":
            raise ScopeViolationError(self.role, "write", raw, "Cannot overwrite worktree root")

        first_part = PurePosixPath(rel_posix).parts[0]
        if first_part in _ALWAYS_PROTECTED_PREFIXES:
            raise ScopeViolationError(
                self.role,
                "write",
                raw,
                f"Direct write to protected internal directory '{first_part}' is forbidden",
            )

        for pattern in self.denied_paths:
            if glob_match(rel_posix, pattern):
                raise ScopeViolationError(
                    self.role, "write", raw, f"Matches denied_paths pattern {pattern!r}"
                )

        for pattern in self.deny_gate_files:
            if glob_match(rel_posix, pattern):
                raise ScopeViolationError(
                    self.role, "write", raw, f"Matches deny_gate_files pattern {pattern!r}"
                )

        if not self.allowed_paths:
            raise ScopeViolationError(self.role, "write", raw, "No allowed_paths configured")

        if not any(glob_match(rel_posix, pattern) for pattern in self.allowed_paths):
            raise ScopeViolationError(
                self.role,
                "write",
                raw,
                f"Path '{rel_posix}' is outside allowed_paths {self.allowed_paths}",
            )

        return resolved

    def enforce_read(self, target_path: str | Path) -> Path:
        """Verify ``target_path`` stays contained within ``worktree_root``."""
        resolved, _ = self._resolve_and_check_containment(target_path, "read")
        return resolved

    def enforce_shell(self, command: str) -> list[str]:
        """Validate shell command against injection, git merge, readonly, and prefix allowlist."""
        if not command or not command.strip():
            raise ScopeViolationError(self.role, "shell", command, "Empty shell command")
        if "\x00" in command:
            raise ScopeViolationError(self.role, "shell", command, "Null byte in shell command")

        bad_meta = _has_unquoted_shell_metachar(command)
        if bad_meta is not None:
            raise ScopeViolationError(
                self.role,
                "shell",
                command,
                f"Disallowed shell metacharacter or chaining operator {bad_meta!r}",
            )

        try:
            tokens = shlex.split(command)
        except ValueError as exc:
            raise ScopeViolationError(
                self.role, "shell", command, f"Malformed shell syntax: {exc}"
            ) from exc

        if not tokens:
            raise ScopeViolationError(self.role, "shell", command, "Empty command tokens")

        return self._validate_shell_tokens(tokens, command, check_prefix=True, in_pytest_addopts=False)

    def _validate_shell_tokens(
        self,
        tokens: list[str],
        command: str,
        *,
        check_prefix: bool = True,
        in_pytest_addopts: bool = False,
    ) -> list[str]:
        exe = Path(tokens[0]).name
        exe_lower = exe.lower()

        # Prevent git merge / push / rebase / worktree and external repo flags
        if exe_lower == "git":
            expect_git_output = False
            for i, tok in enumerate(tokens[1:], start=1):
                if expect_git_output:
                    expect_git_output = False
                    if self.readonly:
                        raise ScopeViolationError(
                            self.role,
                            "shell",
                            command,
                            "Read-only role cannot use file-writing git flag '--output'",
                        )
                    self.enforce_write(tok)
                    continue
                if tok == "-C" and i + 1 < len(tokens):
                    self.enforce_read(tokens[i + 1])
                elif tok.startswith("-C") and len(tok) > 2:
                    self.enforce_read(tok[2:])
                elif tok.startswith("--git-dir=") or tok.startswith("--work-tree="):
                    _, val = tok.split("=", 1)
                    self.enforce_read(val)
                elif tok in ("--git-dir", "--work-tree"):
                    raise ScopeViolationError(
                        self.role, "shell", command, f"Flag {tok!r} is disallowed"
                    )
                elif tok == "--output":
                    if self.readonly:
                        raise ScopeViolationError(
                            self.role,
                            "shell",
                            command,
                            "Read-only role cannot use file-writing git flag '--output'",
                        )
                    if i + 1 >= len(tokens):
                        raise ScopeViolationError(
                            self.role, "shell", command, "Missing target path for '--output'"
                        )
                    expect_git_output = True
                elif tok.startswith("--output="):
                    if self.readonly:
                        raise ScopeViolationError(
                            self.role,
                            "shell",
                            command,
                            "Read-only role cannot use file-writing git flag '--output'",
                        )
                    _, out_val = tok.split("=", 1)
                    self.enforce_write(out_val)
                elif tok == "--ext-diff" or tok.startswith("--ext-diff="):
                    if self.readonly:
                        raise ScopeViolationError(
                            self.role,
                            "shell",
                            command,
                            "Read-only role cannot use git '--ext-diff' flag",
                        )

            subcmd = next((t for t in tokens[1:] if not t.startswith("-")), None)
            if subcmd in _FORBIDDEN_GIT_SUBCOMMANDS:
                raise ScopeViolationError(
                    self.role,
                    "shell",
                    command,
                    f"Git subcommand 'git {subcmd}' is forbidden for workers",
                )
            if self.readonly and subcmd in _READONLY_MUTATING_GIT_SUBCOMMANDS:
                raise ScopeViolationError(
                    self.role,
                    "shell",
                    command,
                    f"Read-only role cannot execute mutating git command 'git {subcmd}'",
                )

        # Restrict inline code execution flags and `-m <module>` for python across all roles
        python_module: str | None = None
        python_module_end_idx: int | None = None
        cov_nested_module: str | None = None
        cov_nested_end_idx: int | None = None
        if exe_lower == "python" or exe_lower.startswith("python3") or exe_lower.startswith("python2"):
            skip_next_py = False
            expect_py_module = False
            for idx, tok in enumerate(tokens[1:], start=1):
                if expect_py_module:
                    python_module = tok
                    python_module_end_idx = idx
                    if python_module not in _ALLOWED_PYTHON_MODULES:
                        raise ScopeViolationError(
                            self.role,
                            "shell",
                            command,
                            f"Python module {python_module!r} is not in allowed_python_modules {sorted(_ALLOWED_PYTHON_MODULES)}",
                        )
                    expect_py_module = False
                    break
                if skip_next_py:
                    skip_next_py = False
                    continue
                if tok == "--":
                    break
                if tok in ("-W", "-X", "--check-hash-based-pycs"):
                    skip_next_py = True
                    continue
                if tok.startswith(("-W", "-X")) and not tok.startswith("--"):
                    continue
                if not tok.startswith("-"):
                    break
                if not tok.startswith("--"):
                    if "c" in tok[1:]:
                        raise ScopeViolationError(
                            self.role,
                            "shell",
                            command,
                            "Inline 'python -c' code execution is disallowed",
                        )
                    if "m" in tok[1:]:
                        m_idx = tok.index("m", 1)
                        mod_rest = tok[m_idx + 1 :]
                        if mod_rest:
                            python_module = mod_rest
                            python_module_end_idx = idx
                            if python_module not in _ALLOWED_PYTHON_MODULES:
                                raise ScopeViolationError(
                                    self.role,
                                    "shell",
                                    command,
                                    f"Python module {python_module!r} is not in allowed_python_modules {sorted(_ALLOWED_PYTHON_MODULES)}",
                                )
                            break
                        expect_py_module = True
                        continue
            if expect_py_module:
                raise ScopeViolationError(
                    self.role,
                    "shell",
                    command,
                    "Missing module name after 'python -m'",
                )

            if python_module == "coverage" and python_module_end_idx is not None:
                cov_subcmd: str | None = None
                cov_subcmd_idx: int | None = None
                skip_next_cov = False
                for idx in range(python_module_end_idx + 1, len(tokens)):
                    tok = tokens[idx]
                    if skip_next_cov:
                        skip_next_cov = False
                        continue
                    if tok in ("--rcfile", "--debug"):
                        skip_next_cov = True
                        continue
                    if tok.startswith("--"):
                        if tok in ("--command",) or tok.startswith("--command="):
                            raise ScopeViolationError(
                                self.role,
                                "shell",
                                command,
                                "Inline code execution in 'python -m coverage' is disallowed",
                            )
                        continue
                    if tok.startswith("-"):
                        if "c" in tok[1:]:
                            raise ScopeViolationError(
                                self.role,
                                "shell",
                                command,
                                "Inline '-c' code execution in 'python -m coverage' is disallowed",
                            )
                        continue
                    cov_subcmd = tok
                    cov_subcmd_idx = idx
                    break

                if cov_subcmd == "run" and cov_subcmd_idx is not None:
                    skip_next_run = False
                    expect_cov_mod = False
                    for idx in range(cov_subcmd_idx + 1, len(tokens)):
                        tok = tokens[idx]
                        if expect_cov_mod:
                            cov_nested_module = tok
                            cov_nested_end_idx = idx
                            if (
                                cov_nested_module not in _ALLOWED_PYTHON_MODULES
                                or cov_nested_module == "coverage"
                            ):
                                raise ScopeViolationError(
                                    self.role,
                                    "shell",
                                    command,
                                    f"Nested coverage module {cov_nested_module!r} is not in allowed_python_modules {sorted(_ALLOWED_PYTHON_MODULES - {'coverage'})}",
                                )
                            expect_cov_mod = False
                            break
                        if skip_next_run:
                            skip_next_run = False
                            continue
                        if tok == "--":
                            continue
                        if tok in (
                            "--data-file",
                            "--rcfile",
                            "--source",
                            "--include",
                            "--omit",
                            "--concurrency",
                            "--context",
                            "--debug",
                        ):
                            skip_next_run = True
                            continue
                        if tok in ("-m", "--module"):
                            expect_cov_mod = True
                            continue
                        if tok.startswith("--module="):
                            cov_nested_module = tok.split("=", 1)[1]
                            cov_nested_end_idx = idx
                            if (
                                not cov_nested_module
                                or cov_nested_module not in _ALLOWED_PYTHON_MODULES
                                or cov_nested_module == "coverage"
                            ):
                                raise ScopeViolationError(
                                    self.role,
                                    "shell",
                                    command,
                                    f"Nested coverage module {cov_nested_module!r} is not in allowed_python_modules {sorted(_ALLOWED_PYTHON_MODULES - {'coverage'})}",
                                )
                            break
                        if tok in ("--command",) or tok.startswith("--command="):
                            raise ScopeViolationError(
                                self.role,
                                "shell",
                                command,
                                "Inline code execution in 'python -m coverage run' is disallowed",
                            )
                        if tok.startswith("-") and not tok.startswith("--"):
                            if "c" in tok[1:]:
                                raise ScopeViolationError(
                                    self.role,
                                    "shell",
                                    command,
                                    "Inline '-c' code execution in 'python -m coverage run' is disallowed",
                                )
                            if "m" in tok[1:]:
                                m_idx = tok.index("m", 1)
                                mod_rest = tok[m_idx + 1 :]
                                if mod_rest:
                                    cov_nested_module = mod_rest
                                    cov_nested_end_idx = idx
                                    if (
                                        cov_nested_module not in _ALLOWED_PYTHON_MODULES
                                        or cov_nested_module == "coverage"
                                    ):
                                        raise ScopeViolationError(
                                            self.role,
                                            "shell",
                                            command,
                                            f"Nested coverage module {cov_nested_module!r} is not in allowed_python_modules {sorted(_ALLOWED_PYTHON_MODULES - {'coverage'})}",
                                        )
                                    break
                                expect_cov_mod = True
                                continue
                    if expect_cov_mod:
                        raise ScopeViolationError(
                            self.role,
                            "shell",
                            command,
                            "Missing module name after 'coverage run -m'",
                        )

        is_pytest = (
            exe_lower == "pytest"
            or python_module == "pytest"
            or cov_nested_module == "pytest"
        )
        is_coverage = python_module == "coverage"
        is_ruff = (
            exe_lower == "ruff"
            or python_module == "ruff"
            or cov_nested_module == "ruff"
        )
        ruff_tokens: list[str] = []
        if is_ruff:
            if exe_lower == "ruff":
                ruff_tokens = tokens[1:]
            elif python_module == "ruff" and python_module_end_idx is not None:
                ruff_tokens = tokens[python_module_end_idx + 1 :]
            elif cov_nested_module == "ruff" and cov_nested_end_idx is not None:
                ruff_tokens = tokens[cov_nested_end_idx + 1 :]

        ruff_subcmd: str | None = None
        has_ruff_fix_flag = False
        if is_ruff:
            skip_ruff_val = False
            for rt in ruff_tokens:
                if skip_ruff_val:
                    skip_ruff_val = False
                    continue
                if rt == "--":
                    break
                if rt in _RUFF_VALUE_FLAGS:
                    skip_ruff_val = True
                    continue
                if rt.startswith("-"):
                    if rt in ("--fix", "--fix-only", "--unsafe-fixes", "--add-noqa"):
                        has_ruff_fix_flag = True
                    continue
                if ruff_subcmd is None:
                    ruff_subcmd = rt
        is_ruff_mutating = is_ruff and (ruff_subcmd == "format" or has_ruff_fix_flag)

        if exe_lower in ("node", "nodejs"):
            skip_next_node = False
            for tok in tokens[1:]:
                if skip_next_node:
                    skip_next_node = False
                    continue
                if tok == "--":
                    break
                if tok in ("-r", "--require", "--import", "--loader"):
                    skip_next_node = True
                    continue
                if not tok.startswith("-"):
                    break
                if tok in ("-e", "--eval", "-p", "--print") or tok.startswith(
                    ("--eval=", "--print=")
                ):
                    raise ScopeViolationError(
                        self.role,
                        "shell",
                        command,
                        "Inline 'node -e/--eval' code execution is disallowed",
                    )
                if not tok.startswith("--") and ("e" in tok[1:] or "p" in tok[1:]):
                    raise ScopeViolationError(
                        self.role,
                        "shell",
                        command,
                        "Inline 'node -e/-p' code execution is disallowed",
                    )

        if self.readonly:
            if exe_lower in _READONLY_MUTATING_CMDS:
                raise ScopeViolationError(
                    self.role,
                    "shell",
                    command,
                    f"Read-only role cannot execute mutating command {exe!r}",
                )
            if exe_lower == "sed" and any(t == "-i" or t.startswith("-i") for t in tokens[1:]):
                raise ScopeViolationError(
                    self.role, "shell", command, "Read-only role cannot run 'sed -i'"
                )
            if is_ruff_mutating:
                raise ScopeViolationError(
                    self.role, "shell", command, "Read-only role cannot run mutating ruff command"
                )
            for t in tokens[1:]:
                t_flag = t.split("=", 1)[0]
                if (
                    t_flag in _FILE_WRITING_FLAGS
                    or t == "--ext-diff"
                    or t.startswith("--ext-diff=")
                    or t == "-o"
                    or (t.startswith("-o") and not t.startswith("--"))
                    or (
                        is_pytest
                        and (
                            t == "--override-ini"
                            or t.startswith("--override-ini=")
                            or _parse_bundled_pytest_o(t)[0]
                        )
                    )
                    or (
                        is_coverage
                        and (
                            t_flag in _COVERAGE_OUTPUT_FLAGS
                            or (t.startswith(("-d", "-o")) and not t.startswith("--"))
                        )
                    )
                ):
                    raise ScopeViolationError(
                        self.role,
                        "shell",
                        command,
                        f"Read-only role cannot use file-writing flag {t_flag!r}",
                    )

        if check_prefix:
            if not self.allowed_shell_prefixes:
                raise ScopeViolationError(
                    self.role, "shell", command, "No allowed_shell_prefixes configured"
                )

            matched_prefix = False
            for prefix in self.allowed_shell_prefixes:
                try:
                    prefix_tokens = shlex.split(prefix)
                except ValueError:
                    continue
                if not prefix_tokens:
                    continue
                if len(tokens) >= len(prefix_tokens) and tokens[: len(prefix_tokens)] == prefix_tokens:
                    matched_prefix = True
                    break

            if not matched_prefix:
                raise ScopeViolationError(
                    self.role,
                    "shell",
                    command,
                    f"Command {command!r} does not match allowed_shell_prefixes {self.allowed_shell_prefixes}",
                )

        # Ensure file-writing flags (both `--flag=path` and `--flag path`) and path-like tokens stay in scope
        expect_write_flag: str | None = None
        expect_pytest_ini = False

        for idx, tok in enumerate(tokens[1:], start=1):
            in_cov_prefix = (
                is_coverage
                and python_module_end_idx is not None
                and idx > python_module_end_idx
                and (cov_nested_end_idx is None or idx <= cov_nested_end_idx)
            )
            cov_flag_active = in_cov_prefix or (is_coverage and cov_nested_module is None)

            if expect_write_flag is not None:
                flag_used = expect_write_flag
                expect_write_flag = None
                if self.readonly:
                    raise ScopeViolationError(
                        self.role,
                        "shell",
                        command,
                        f"Read-only role cannot use file-writing flag {flag_used!r}",
                    )
                self.enforce_write(tok)
                continue

            if expect_pytest_ini:
                expect_pytest_ini = False
                self._check_pytest_override_ini(
                    tok, command, in_pytest_addopts=in_pytest_addopts
                )
                continue

            if (
                tok in _FILE_WRITING_FLAGS
                or (not is_pytest and tok == "-o")
                or (cov_flag_active and tok in _COVERAGE_OUTPUT_FLAGS)
            ):
                if self.readonly:
                    raise ScopeViolationError(
                        self.role,
                        "shell",
                        command,
                        f"Read-only role cannot use file-writing flag {tok!r}",
                    )
                expect_write_flag = tok
                continue

            if is_pytest and tok in ("-o", "--override-ini"):
                if self.readonly:
                    raise ScopeViolationError(
                        self.role,
                        "shell",
                        command,
                        f"Read-only role cannot use pytest override flag {tok!r}",
                    )
                expect_pytest_ini = True
                continue

            if tok.startswith("-"):
                # Bundled / glued pytest `-o` clusters (`-qo`, `-vo`, `-qolog_file=...`, `-qo=...`)
                # must be checked BEFORE `if "=" in tok:` and before falling through to `tok[2:]`.
                if (
                    is_pytest
                    and not in_cov_prefix
                    and not tok.startswith("--")
                    and len(tok) > 2
                ):
                    found_o, attached_o, empty_eq = _parse_bundled_pytest_o(tok)
                    if found_o:
                        if self.readonly:
                            raise ScopeViolationError(
                                self.role,
                                "shell",
                                command,
                                "Read-only role cannot override pytest ini via '-o'",
                            )
                        if empty_eq:
                            raise ScopeViolationError(
                                self.role,
                                "shell",
                                command,
                                "Missing value for pytest '-o' flag",
                            )
                        if attached_o is None:
                            expect_pytest_ini = True
                        else:
                            self._check_pytest_override_ini(
                                attached_o, command, in_pytest_addopts=in_pytest_addopts
                            )
                        continue

                # Glued short flags (`-o<val>`, `-d<val>`) must be checked BEFORE `if "=" in tok:`
                # so `-olog_file=.thread/policy.yaml` is never treated as `--flag=val`.
                if (
                    not tok.startswith("--")
                    and tok.startswith("-o")
                    and len(tok) > 2
                    and not tok.startswith("-o=")
                ):
                    attached = tok[2:]
                    if is_pytest and not in_cov_prefix:
                        if self.readonly:
                            raise ScopeViolationError(
                                self.role,
                                "shell",
                                command,
                                "Read-only role cannot override pytest ini via '-o'",
                            )
                        self._check_pytest_override_ini(
                            attached, command, in_pytest_addopts=in_pytest_addopts
                        )
                    else:
                        if self.readonly:
                            raise ScopeViolationError(
                                self.role,
                                "shell",
                                command,
                                "Read-only role cannot use file-writing flag '-o'",
                            )
                        self.enforce_write(attached)
                    continue

                if (
                    cov_flag_active
                    and not tok.startswith("--")
                    and tok.startswith("-d")
                    and len(tok) > 2
                    and not tok.startswith("-d=")
                ):
                    if self.readonly:
                        raise ScopeViolationError(
                            self.role,
                            "shell",
                            command,
                            "Read-only role cannot use file-writing flag '-d'",
                        )
                    self.enforce_write(tok[2:])
                    continue

                if "=" in tok:
                    flag_name, flag_val = tok.split("=", 1)
                    if (
                        flag_name in _FILE_WRITING_FLAGS
                        or ((not is_pytest or in_cov_prefix) and flag_name == "-o")
                        or (cov_flag_active and flag_name in _COVERAGE_OUTPUT_FLAGS)
                    ):
                        if self.readonly:
                            raise ScopeViolationError(
                                self.role,
                                "shell",
                                command,
                                f"Read-only role cannot use file-writing flag {flag_name!r}",
                            )
                        if not flag_val:
                            raise ScopeViolationError(
                                self.role,
                                "shell",
                                command,
                                f"Missing target path for file-writing flag {flag_name!r}",
                            )
                        self.enforce_write(flag_val)
                        continue
                    if is_pytest and flag_name in ("--override-ini", "-o"):
                        if self.readonly:
                            raise ScopeViolationError(
                                self.role,
                                "shell",
                                command,
                                f"Read-only role cannot override pytest ini via {flag_name!r}",
                            )
                        self._check_pytest_override_ini(
                            flag_val, command, in_pytest_addopts=in_pytest_addopts
                        )
                        continue
                    candidates = [flag_val]
                    if ":" in flag_val and not (len(flag_val) >= 2 and flag_val[1] == ":"):
                        candidates.extend(seg for seg in flag_val.split(":") if seg)
                    for cand in candidates:
                        if "/" in cand or "\\" in cand or ".." in cand or Path(cand).is_absolute():
                            file_part = cand.split("::", 1)[0]
                            if file_part:
                                self._resolve_and_check_containment(file_part, "read")
                elif len(tok) > 2 and not tok.startswith("--"):
                    attached = tok[2:]
                    if "/" in attached or "\\" in attached or ".." in attached:
                        file_part = attached.split("::", 1)[0]
                        if file_part:
                            self._resolve_and_check_containment(file_part, "read")
                continue

            if "/" in tok or "\\" in tok or ".." in tok or Path(tok).is_absolute():
                # Allow pytest nodeids like tests/test_a.py::test_fn by stripping ::nodeid
                file_part = tok.split("::", 1)[0]
                if file_part:
                    self._resolve_and_check_containment(file_part, "read")

        if expect_write_flag is not None:
            raise ScopeViolationError(
                self.role,
                "shell",
                command,
                f"Missing target path for file-writing flag {expect_write_flag!r}",
            )
        if expect_pytest_ini:
            raise ScopeViolationError(
                self.role,
                "shell",
                command,
                "Missing value for pytest '-o'/'--override-ini' flag",
            )

        if is_ruff_mutating:
            ruff_targets: list[str] = []
            skip_ruff_val = False
            saw_ruff_subcmd = False
            after_double_dash = False
            for rt in ruff_tokens:
                if after_double_dash:
                    ruff_targets.append(rt)
                    continue
                if skip_ruff_val:
                    skip_ruff_val = False
                    continue
                if rt == "--":
                    after_double_dash = True
                    continue
                if rt in _RUFF_VALUE_FLAGS:
                    skip_ruff_val = True
                    continue
                if rt.startswith("-"):
                    continue
                if not saw_ruff_subcmd and rt in ("format", "check"):
                    saw_ruff_subcmd = True
                    continue
                ruff_targets.append(rt)

            if not ruff_targets:
                ruff_targets = ["."]
            for r_target in ruff_targets:
                resolved_target = self.enforce_write(r_target)
                rel_norm = (
                    resolved_target.relative_to(self.worktree_root).as_posix().rstrip("/")
                )
                is_dir_target = (
                    resolved_target.is_dir()
                    or r_target.endswith(("/", "\\"))
                    or rel_norm == "."
                    or (not resolved_target.exists() and not PurePosixPath(rel_norm).suffix)
                )
                rel_parts = tuple(p for p in PurePosixPath(rel_norm).parts if p not in ("", "."))
                for pat in (*self.denied_paths, *self.deny_gate_files):
                    pat_parts = _normalize_pattern(pat)
                    pat_norm = "/".join(pat_parts)
                    if pat_norm and (
                        pat_norm == rel_norm
                        or pat_norm.startswith(f"{rel_norm}/")
                        or (is_dir_target and _pattern_can_match_under_dir(rel_parts, pat_parts))
                    ):
                        raise ScopeViolationError(
                            self.role,
                            "shell",
                            command,
                            f"Mutating ruff target {r_target!r} covers protected/denied pattern {pat!r}",
                        )

        return tokens

    def _check_pytest_override_ini(
        self, val: str, command: str, *, in_pytest_addopts: bool = False
    ) -> None:
        if "=" in val:
            ini_key, ini_val = val.split("=", 1)
            key_lower = ini_key.strip().lower()
            if key_lower == "addopts":
                if self.readonly:
                    raise ScopeViolationError(
                        self.role,
                        "shell",
                        command,
                        f"Read-only role cannot override pytest ini {ini_key!r}",
                    )
                if in_pytest_addopts:
                    raise ScopeViolationError(
                        self.role,
                        "shell",
                        command,
                        "Nested pytest 'addopts' override is disallowed",
                    )
                if "\x00" in ini_val:
                    raise ScopeViolationError(
                        self.role,
                        "shell",
                        command,
                        "Null byte in pytest addopts override",
                    )
                bad_meta = _has_unquoted_shell_metachar(ini_val)
                if bad_meta is not None:
                    raise ScopeViolationError(
                        self.role,
                        "shell",
                        command,
                        f"Disallowed shell metacharacter {bad_meta!r} in pytest addopts override",
                    )
                try:
                    addopts_tokens = shlex.split(ini_val)
                except ValueError as exc:
                    raise ScopeViolationError(
                        self.role,
                        "shell",
                        command,
                        f"Malformed pytest addopts override syntax: {exc}",
                    ) from exc
                if not addopts_tokens:
                    return
                for atok in addopts_tokens:
                    if (
                        atok in ("-c", "--config-file", "--rootdir", "--confcutdir", "--debug")
                        or atok.startswith(
                            ("--config-file=", "--rootdir=", "--confcutdir=", "--debug=")
                        )
                        or _has_pytest_c_flag(atok)
                    ):
                        raise ScopeViolationError(
                            self.role,
                            "shell",
                            command,
                            f"Disallowed pytest config/rootdir flag {atok!r} in addopts override",
                        )
                self._validate_shell_tokens(
                    ["pytest", *addopts_tokens],
                    command,
                    check_prefix=False,
                    in_pytest_addopts=True,
                )
                return
            if key_lower in ("log_file", "cache_dir", "basetemp", "resultlog"):
                if self.readonly:
                    raise ScopeViolationError(
                        self.role,
                        "shell",
                        command,
                        f"Read-only role cannot override pytest ini {ini_key!r}",
                    )
                self.enforce_write(ini_val.strip())
                return
            if "/" in ini_val or "\\" in ini_val or ".." in ini_val or Path(ini_val).is_absolute():
                self._resolve_and_check_containment(ini_val.strip(), "read")

    def _extract_tool_paths(
        self,
        args: dict[str, Any],
        *,
        include_patches: bool = True,
        extra_keys: frozenset[str] = frozenset(),
    ) -> list[str]:
        extracted: list[str] = []

        def _walk_path_container(val: Any) -> None:
            if isinstance(val, str) and val.strip():
                extracted.append(val.strip())
            elif isinstance(val, (list, tuple)):
                for item in val:
                    if isinstance(item, str) and item.strip():
                        extracted.append(item.strip())
                    elif isinstance(item, (dict, list, tuple)):
                        _walk(item)
            elif isinstance(val, dict):
                _walk(val)

        def _walk(node: Any) -> None:
            if isinstance(node, dict):
                for key, val in node.items():
                    if key in _PATH_ARG_KEYS or key in extra_keys:
                        if isinstance(val, str) and val.strip():
                            extracted.append(val.strip())
                        elif isinstance(val, (list, tuple, dict)):
                            _walk_path_container(val)
                    elif key in _PATH_LIST_KEYS:
                        _walk_path_container(val)
                    elif include_patches and key in ("patch", "diff", "input", "raw"):
                        if isinstance(val, str):
                            extracted.extend(_extract_patch_paths(val))
                        elif isinstance(val, (dict, list, tuple)):
                            _walk(val)
                    elif isinstance(val, (dict, list, tuple)):
                        _walk(val)
            elif isinstance(node, (list, tuple)):
                for item in node:
                    if isinstance(item, (dict, list, tuple)):
                        _walk(item)

        _walk(args)
        return extracted

    def enforce_tool_call(
        self, tool_name: str, tool_args: dict[str, Any] | str | None
    ) -> None:
        """Fail-closed validation of an agent tool invocation prior to execution."""
        norm_name = tool_name.strip().lower()
        args: dict[str, Any]
        if tool_args is None:
            args = {}
        elif isinstance(tool_args, str):
            try:
                parsed = json.loads(tool_args)
                args = parsed if isinstance(parsed, dict) else {"raw": tool_args}
            except json.JSONDecodeError:
                args = {"raw": tool_args}
        elif isinstance(tool_args, dict):
            args = tool_args
        else:
            args = {}

        if norm_name in _WRITE_TOOLS or (
            norm_name not in _READ_TOOLS
            and any(
                k in norm_name
                for k in (
                    "write",
                    "edit",
                    "patch",
                    "create",
                    "delete",
                    "remove",
                    "unlink",
                    "move",
                    "rename",
                    "save",
                    "mkdir",
                    "rmdir",
                    "truncate",
                )
            )
        ):
            extracted = self._extract_tool_paths(args)
            if not extracted:
                raise ScopeViolationError(
                    self.role,
                    "tool",
                    tool_name,
                    "Write/edit tool call missing extractable target path (fail closed)",
                )
            for target in extracted:
                self.enforce_write(target)
            return

        if norm_name in _SHELL_TOOLS or any(k in norm_name for k in ("bash", "shell", "exec")):
            cwd_val = args.get("cwd") or args.get("working_directory") or args.get("workingDirectory")
            if isinstance(cwd_val, str) and cwd_val.strip():
                self.enforce_read(cwd_val.strip())
            cmd_val: str | None = None
            for key in _SHELL_CMD_KEYS:
                val = args.get(key)
                if isinstance(val, str) and val.strip():
                    cmd_val = val
                    break
            if cmd_val is None and isinstance(args.get("raw"), str):
                cmd_val = args["raw"]
            if not cmd_val:
                raise ScopeViolationError(
                    self.role,
                    "tool",
                    tool_name,
                    "Shell tool call missing command argument (fail closed)",
                )
            self.enforce_shell(cmd_val)
            return

        if norm_name in _READ_TOOLS:
            for target in self._extract_tool_paths(
                args, include_patches=False, extra_keys=_READ_EXTRA_PATH_KEYS
            ):
                self.enforce_read(target)
            return

        if norm_name in ("git_merge", "git_push", "merge", "push"):
            raise ScopeViolationError(
                self.role, "tool", tool_name, "Workers are forbidden from merging or pushing"
            )

        if self.readonly:
            raise ScopeViolationError(
                self.role,
                "tool",
                tool_name,
                f"Read-only role cannot invoke unrecognized or mutating tool {tool_name!r}",
            )

        # Unrecognized tools carrying path args must be write-checked (fail closed),
        # while read/search directory keys must still satisfy worktree read containment.
        for target in self._extract_tool_paths(args):
            self.enforce_write(target)
        for target in self._extract_tool_paths(
            args, include_patches=False, extra_keys=_READ_EXTRA_PATH_KEYS
        ):
            self.enforce_read(target)


def _run_pre_tool_use_hook() -> int:
    """Entrypoint invoked by Copilot CLI `preToolUse` hook via `python -m thread_sdlc.workers.permissions`."""
    policy_path = os.environ.get("THREAD_POLICY_PATH")
    policy_json = os.environ.get("THREAD_POLICY_JSON")
    sentinel_path = os.environ.get("THREAD_VIOLATION_SENTINEL")

    try:
        if policy_path:
            policy_data = json.loads(Path(policy_path).read_text(encoding="utf-8"))
        elif policy_json:
            policy_data = json.loads(policy_json)
        else:
            print(
                json.dumps(
                    {
                        "permissionDecision": "deny",
                        "permissionDecisionReason": "Missing THREAD_POLICY_PATH / THREAD_POLICY_JSON",
                    }
                )
            )
            return 0
        policy = RolePolicy.from_dict(policy_data)
    except Exception as exc:  # fail closed if policy cannot load
        print(
            json.dumps(
                {
                    "permissionDecision": "deny",
                    "permissionDecisionReason": f"Failed to load RolePolicy: {exc}",
                }
            )
        )
        return 0

    raw_stdin = sys.stdin.read()
    try:
        payload = json.loads(raw_stdin) if raw_stdin.strip() else {}
    except json.JSONDecodeError as exc:
        print(
            json.dumps(
                {
                    "permissionDecision": "deny",
                    "permissionDecisionReason": f"Invalid preToolUse JSON input: {exc}",
                }
            )
        )
        return 0

    tool_name = str(payload.get("toolName") or payload.get("tool_name") or "")
    tool_args = payload.get("toolArgs") if "toolArgs" in payload else payload.get("tool_args")

    try:
        policy.enforce_tool_call(tool_name, tool_args)
    except ScopeViolationError as err:
        if sentinel_path:
            sp = Path(sentinel_path)
            sp.parent.mkdir(parents=True, exist_ok=True)
            tmp_sp = sp.with_suffix(".tmp")
            tmp_sp.write_text(
                json.dumps(
                    {
                        "role": err.role,
                        "operation": err.operation,
                        "target": err.target,
                        "reason": err.reason,
                        "message": str(err),
                    }
                ),
                encoding="utf-8",
            )
            tmp_sp.replace(sp)
        print(
            json.dumps(
                {
                    "permissionDecision": "deny",
                    "permissionDecisionReason": str(err),
                }
            )
        )
        return 0

    print(json.dumps({"permissionDecision": "allow"}))
    return 0


if __name__ == "__main__":
    raise SystemExit(_run_pre_tool_use_hook())
