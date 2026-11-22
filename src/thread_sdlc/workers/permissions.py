"""Fail-closed RolePolicy enforcement, Python 3.11 glob matching, and Copilot CLI preToolUse hook."""

from __future__ import annotations

import configparser
import fnmatch
import json
import os
import re
import shlex
import sys
import tomllib
from collections.abc import Mapping
from pathlib import Path, PurePosixPath
from typing import Any, Literal, NoReturn
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
        "run_cmd",
        "execute",
        "terminal",
        "powershell",
        "pwsh",
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

# Reviewed command forms. Git helpers and commands with repository-wide side
# effects require a separate policy; they cannot inherit a broad "git" prefix.
_GIT_INSPECTION_OPTIONS = {
    "status": {"--short", "-s", "--branch", "-b", "--porcelain", "--porcelain=v1", "--porcelain=v2", "--ignored"},
    "diff": {"--stat", "--name-only", "--name-status", "--cached", "--staged", "--check", "--summary", "--numstat", "--no-color", "--no-ext-diff", "--no-textconv", "-w", "-U0"},
    "log": {"--oneline", "--stat", "--name-only", "--graph", "--decorate", "--no-decorate", "--all", "--no-color"},
    "show": {"--oneline", "--stat", "--name-only", "--no-color", "--no-ext-diff", "--no-textconv"},
    "ls-files": {"--cached", "--modified", "--deleted", "--others", "--exclude-standard", "-z"},
    "rev-parse": {"--short", "--verify", "--abbrev-ref", "--show-toplevel", "--is-inside-work-tree"},
}

_PATH_ARG_KEYS = (
    "path",
    "file_path",
    "filePath",
    "target_path",
    "targetPath",
    "target_file",
    "targetFile",
    "TargetFile",
    "target_file_path",
    "targetFilePath",
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
    "fileName",
    "old_file_name",
    "oldFileName",
    "new_file_name",
    "newFileName",
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
        "file_names",
        "fileNames",
        "targets",
        "roots",
        "directories",
        "dirs",
        "urls",
        "uris",
    }
)

_PYTEST_VALUE_SHORT_FLAGS = frozenset({"k", "m", "c", "r", "W", "p"})

_PYTEST_VALUE_LONG_FLAGS = frozenset(
    {
        "--maxfail",
        "--pdbcls",
        "--capture",
        "--lfnf",
        "--last-failed-no-failures",
        "--durations",
        "--durations-min",
        "--verbosity",
        "--report-chars",
        "--tb",
        "--show-capture",
        "--color",
        "--code-highlight",
        "--pastebin",
        "--junitprefix",
        "--junit-prefix",
        "--pythonwarnings",
        "--max-warnings",
        "--ignore",
        "--ignore-glob",
        "--deselect",
        "--confcutdir",
        "--import-mode",
        "--doctest-report",
        "--doctest-glob",
        "--assert",
        "--log-level",
        "--log-format",
        "--log-date-format",
        "--log-cli-level",
        "--log-cli-format",
        "--log-cli-date-format",
        "--log-file-mode",
        "--log-file-level",
        "--log-file-format",
        "--log-file-date-format",
        "--log-auto-indent",
        "--log-disable",
    }
)

_PYTEST_CONFIG_FILENAMES = (
    "pytest.toml",
    ".pytest.toml",
    "pytest.ini",
    ".pytest.ini",
    "pyproject.toml",
    "tox.ini",
    "setup.cfg",
)

_ALLOWED_PYTEST_ROOT_CONFIGS = frozenset(_PYTEST_CONFIG_FILENAMES)

_PYTEST_INSPECTED_INI_KEYS = frozenset(
    {
        "addopts",
        "log_file",
        "cache_dir",
        "basetemp",
        "resultlog",
        "testpaths",
        "pythonpath",
        "norecursedirs",
    }
)

_READ_EXTRA_PATH_KEYS = frozenset(
    {
        "cwd",
        "working_directory",
        "workingDirectory",
        "resolved_working_directory",
        "resolvedWorkingDirectory",
        "search_path",
        "searchPath",
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

_SHELL_CMD_KEYS = (
    "command",
    "cmd",
    "script",
    "command_line",
    "commandLine",
    "CommandLine",
    "full_command_text",
    "fullCommandText",
    "shell_command",
    "shellCommand",
)
_SHELL_CWD_KEYS = (
    "cwd",
    "working_directory",
    "workingDirectory",
    "resolved_working_directory",
    "resolvedWorkingDirectory",
)

_SHELL_NAME_TOKENS = frozenset(
    {
        "bash",
        "shell",
        "sh",
        "zsh",
        "powershell",
        "pwsh",
        "exec",
        "execute",
        "terminal",
        "command",
        "cmd",
        "cli",
        "spawn",
        "process",
        "script",
    }
)


def _split_tool_name_tokens(tool_name: str) -> list[str]:
    split_acronyms = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", tool_name)
    split_camel = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", split_acronyms)
    return re.findall(r"[a-z0-9]+", split_camel.lower())


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
    Stops scanning at value-taking short options (``k, m, c, r, W, p``) so
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


def _parse_bundled_pytest_c(tok: str) -> tuple[bool, str | None, bool]:
    """Inspect a short pytest option cluster like ``-qc`` or ``-vc<path>``.

    Returns ``(found_c, attached_val_or_none, has_empty_equals)``.
    Stops scanning at value-taking short options (``k, m, r, W, p`` and ``o``)
    so expressions like ``-kc`` or ``-oc`` are never mistaken for ``-c``.
    """
    if not tok.startswith("-") or tok.startswith("--") or len(tok) <= 2:
        return False, None, False
    chars = tok[1:]
    value_stops = (_PYTEST_VALUE_SHORT_FLAGS - {"c"}) | {"o"}
    for j, ch in enumerate(chars):
        if ch in value_stops:
            return False, None, False
        if ch == "c":
            rest = chars[j + 1 :]
            if not rest:
                return True, None, False
            if rest.startswith("="):
                val = rest[1:]
                return True, val, (val == "")
            return True, rest, False
    return False, None, False


def _parse_bundled_pytest_p(tok: str) -> tuple[bool, str | None]:
    """Inspect a short pytest option cluster like ``-qp`` or ``-qpno:cacheprovider``."""
    if not tok.startswith("-") or tok.startswith("--") or len(tok) <= 2:
        return False, None
    chars = tok[1:]
    value_stops = (_PYTEST_VALUE_SHORT_FLAGS - {"p"}) | {"o"}
    for j, ch in enumerate(chars):
        if ch in value_stops:
            return False, None
        if ch == "p":
            rest = chars[j + 1 :]
            return True, (rest if rest else None)
    return False, None


def _pytest_short_flag_expects_next_value(tok: str) -> bool:
    """Return True if a short pytest option cluster ends with a non-c/o value flag."""
    if not tok.startswith("-") or tok.startswith("--") or len(tok) < 2:
        return False
    for j, ch in enumerate(tok[1:]):
        if ch in ("c", "o"):
            return False
        if ch in _PYTEST_VALUE_SHORT_FLAGS:
            return j == len(tok) - 2
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
        self,
        target_path: str | Path,
        operation: Literal["write", "read"],
        *,
        base_dir: Path | None = None,
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
        anchor = base_dir if base_dir is not None else self.worktree_root
        candidate = p if p.is_absolute() else (anchor / p)

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

    def enforce_write(
        self, target_path: str | Path, *, base_dir: Path | None = None
    ) -> Path:
        """Verify ``target_path`` may be written by this role before touching disk."""
        raw = str(target_path)
        if self.readonly:
            raise ScopeViolationError(
                self.role, "write", raw, "Read-only role cannot write or modify files"
            )

        resolved, rel_posix = self._resolve_and_check_containment(
            target_path, "write", base_dir=base_dir
        )
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

    def enforce_read(
        self, target_path: str | Path, *, base_dir: Path | None = None
    ) -> Path:
        """Verify ``target_path`` stays contained within ``worktree_root``."""
        resolved, _ = self._resolve_and_check_containment(
            target_path, "read", base_dir=base_dir
        )
        return resolved

    def _compute_lexical_paths(
        self, raw_target: str, *, anchors: list[Path] | None = None
    ) -> list[Path]:
        local_raw = raw_target.strip()
        if not local_raw:
            return []
        if "://" in local_raw or local_raw.lower().startswith("file:"):
            parsed = urlsplit(local_raw)
            if parsed.scheme.lower() != "file":
                return []
            if parsed.netloc and parsed.netloc.lower() != "localhost":
                return []
            if parsed.query or parsed.fragment:
                return []
            local_raw = url2pathname(parsed.path)
            if not local_raw:
                return []

        p = Path(local_raw)
        results: list[Path] = []
        if not p.is_absolute():
            base_anchors = anchors if anchors else [self.worktree_root]
            for anchor in base_anchors:
                lex = Path(os.path.normpath(anchor / p))
                try:
                    lex.relative_to(self.worktree_root)
                except ValueError:
                    continue
                if lex not in results:
                    results.append(lex)
            return results

        norm_p = Path(os.path.normpath(p))
        cur = norm_p
        while True:
            if cur == self.worktree_root or cur.resolve(strict=False) == self.worktree_root:
                rel = norm_p.relative_to(cur)
                lex = Path(os.path.normpath(self.worktree_root / rel))
                try:
                    lex.relative_to(self.worktree_root)
                except ValueError:
                    pass
                else:
                    if lex not in results:
                        results.append(lex)
            if cur.parent == cur:
                break
            cur = cur.parent
        return results

    def _resolve_shell_cwd(
        self, cwd: str | Path | None, command: str
    ) -> tuple[Path, list[Path]]:
        if cwd is None:
            return self.worktree_root, [self.worktree_root]
        if not isinstance(cwd, (str, Path)):
            raise ScopeViolationError(
                self.role, "shell", command, "Invalid working directory type (fail closed)"
            )
        raw_cwd = str(cwd).strip()
        if not raw_cwd:
            raise ScopeViolationError(
                self.role, "shell", command, "Empty working directory (fail closed)"
            )
        resolved_cwd, _ = self._resolve_and_check_containment(raw_cwd, "read")
        if not resolved_cwd.exists() or not resolved_cwd.is_dir():
            raise ScopeViolationError(
                self.role,
                "shell",
                command,
                f"Working directory {raw_cwd!r} does not exist or is not a directory",
            )
        lexical_cwds = self._compute_lexical_paths(raw_cwd)
        if resolved_cwd not in lexical_cwds:
            lexical_cwds.insert(0, resolved_cwd)
        return resolved_cwd, lexical_cwds

    def _validate_shell_cwd_mapping(
        self, mapping: dict[str, Any], command: str
    ) -> str | None:
        entries: list[tuple[str, str, Path]] = []
        for key in _SHELL_CWD_KEYS:
            if key not in mapping or mapping[key] is None:
                continue
            val = mapping[key]
            if not isinstance(val, (str, Path)):
                raise ScopeViolationError(
                    self.role,
                    "shell",
                    command,
                    f"Invalid working directory type for {key!r} (fail closed)",
                )
            raw_val = str(val).strip()
            if not raw_val:
                raise ScopeViolationError(
                    self.role,
                    "shell",
                    command,
                    f"Empty working directory value for {key!r} (fail closed)",
                )
            resolved, _ = self._resolve_and_check_containment(raw_val, "read")
            if not resolved.exists() or not resolved.is_dir():
                raise ScopeViolationError(
                    self.role,
                    "shell",
                    command,
                    f"Working directory {raw_val!r} does not exist or is not a directory",
                )
            entries.append((key, raw_val, resolved))

        if not entries:
            return None

        first_resolved = entries[0][2]
        for key, _, resolved in entries[1:]:
            if resolved != first_resolved:
                raise ScopeViolationError(
                    self.role,
                    "shell",
                    command,
                    f"Conflicting working directory values ({entries[0][0]!r} vs {key!r})",
                )

        for _, raw_val, resolved in entries:
            lex_paths = self._compute_lexical_paths(raw_val)
            if any(lp != resolved for lp in lex_paths):
                return raw_val
        return entries[0][1]

    def enforce_shell(self, command: str, cwd: str | Path | None = None) -> list[str]:
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

        effective_cwd, lexical_cwds = self._resolve_shell_cwd(cwd, command)

        try:
            tokens = shlex.split(command)
        except ValueError as exc:
            raise ScopeViolationError(
                self.role, "shell", command, f"Malformed shell syntax: {exc}"
            ) from exc

        if not tokens:
            raise ScopeViolationError(self.role, "shell", command, "Empty command tokens")

        return self._validate_shell_tokens(
            tokens,
            command,
            check_prefix=True,
            in_pytest_addopts=False,
            effective_cwd=effective_cwd,
            lexical_cwds=lexical_cwds,
        )

    def _validate_git(self, args: list[str], command: str, cwd: Path) -> None:
        """Approve only understood Git operations with explicit operands."""

        def reject(reason: str) -> NoReturn:
            raise ScopeViolationError(self.role, "shell", command, reason)

        def literal(value: str) -> str:
            if (
                not value
                or value != value.strip()
                or value.startswith(("-", "~"))
                or not re.fullmatch(r"[\w./ @+~-]+", value)
            ):
                reject("Git requires literal file or revision operands")
            return value

        def check_path_identity(value: str, base_dir: Path, resolved: Path) -> None:
            # Git pathspecs address the named index entry. Following a symlink
            # to a different file would authorize the wrong entry.
            if Path(os.path.normpath(base_dir / value)) != resolved:
                reject("Git path must identify the same lexical and resolved location")

        def writable(value: str, *, directory: bool = False) -> Path:
            literal(value)
            path = self.enforce_write(value, base_dir=cwd)
            check_path_identity(value, cwd, path)
            rel = path.relative_to(self.worktree_root)
            if any(
                _pattern_can_match_under_dir(rel.parts, _normalize_pattern(pattern))
                for pattern in (*self.denied_paths, *self.deny_gate_files)
            ):
                reject("Git target contains paths excluded by role policy")
            if directory or path.is_dir() or not path.exists():
                # An absent path can still represent a tracked directory. It is
                # safe only when all possible children belong to the role.
                if not any(
                    _normalize_pattern(pattern)[-1:] == ["**"]
                    and glob_match(rel.as_posix(), pattern)
                    for pattern in self.allowed_paths
                ):
                    reject("Git directory scope requires an allowlist covering the entire subtree")
            return path

        git_dir: str | None = None
        while args and args[0].startswith("-"):
            opt, *args = args
            if opt in {"--no-pager", "--no-optional-locks", "--literal-pathspecs"}:
                continue
            if opt.startswith("--git-dir="):
                opt, val = opt.split("=", 1)
            elif opt in {"-C", "-c", "--git-dir"} and args:
                val, *args = args
            else:
                reject("Unsupported Git global option")
            if opt == "-C":
                if git_dir is not None:
                    reject("Git directory must follow working directory selection")
                selected_cwd = self.enforce_read(literal(val), base_dir=cwd)
                check_path_identity(val, cwd, selected_cwd)
                if not selected_cwd.is_dir():
                    reject("Git working directory must exist")
                cwd = selected_cwd
            elif opt == "--git-dir":
                if git_dir is not None:
                    reject("Git directory may only be specified once")
                git_dir = literal(val)
            else:
                key, separator, value = val.partition("=")
                if (
                    self.readonly or not separator or value.lstrip().startswith("!")
                    or key.lower() not in {"user.name", "user.email"}
                ):
                    reject("Unsupported Git configuration override")

        if not args:
            reject("Missing Git operation")
        op, *rest = args
        if op in _GIT_INSPECTION_OPTIONS:
            if git_dir is not None:
                metadata = self.enforce_read(git_dir, base_dir=cwd)
                check_path_identity(git_dir, cwd, metadata)
                if metadata != self.worktree_root / ".git":
                    reject("Git inspection requires the current repository metadata")
            after_separator = False
            for arg in rest:
                if arg == "--" and not after_separator:
                    after_separator = True
                elif not after_separator and (
                    arg in _GIT_INSPECTION_OPTIONS[op]
                    or (op in {"log", "show"} and re.fullmatch(r"-\d+|--max-count=\d+", arg))
                ):
                    continue
                else:
                    self.enforce_read(literal(arg), base_dir=cwd)
            return
        if self.readonly:
            reject("Only read-only Git inspection is available to this role")
        if git_dir is not None and op != "init":
            reject("Explicit Git metadata directory unsupported for this operation")
        if op == "init" and len(rest) == 1:
            destination = writable(rest[0], directory=True)
            # Git enters the destination before interpreting a relative
            # metadata directory. A .git file can redirect metadata elsewhere.
            metadata_operand = git_dir or ".git"
            metadata = self.enforce_read(metadata_operand, base_dir=destination)
            check_path_identity(metadata_operand, destination, metadata)
            if metadata != destination / ".git" or metadata.is_file():
                reject("Git metadata must reside inside the initialized directory")
            return
        if op == "clone":
            if len(rest) != 2 or any(value.startswith("-") for value in rest):
                reject("Git clone requires a local source and an explicit destination without options")
            source, destination = rest
            self.enforce_read(literal(source), base_dir=cwd)
            writable(destination, directory=True)
            return
        if op not in {"add", "restore", "checkout", "mv", "rm"}:
            reject("Git operation has no worker permission policy")
        if op == "checkout" and rest[:1] != ["--"]:
            reject("Git checkout requires an explicit path separator")
        safe_flags = {"rm": {"-f", "--cached"}, "mv": {"-f"}, "restore": {"--staged", "--worktree"}}
        while rest and rest[0] in safe_flags.get(op, ()):
            rest = rest[1:]
        if rest[:1] == ["--"]:
            rest = rest[1:]
        if not rest or (op == "mv" and len(rest) < 2):
            reject("Git operation requires explicit file operands")
        for value in rest:
            writable(value)

    def _validate_shell_tokens(
        self,
        tokens: list[str],
        command: str,
        *,
        check_prefix: bool = True,
        in_pytest_addopts: bool = False,
        effective_cwd: Path | None = None,
        lexical_cwds: list[Path] | None = None,
    ) -> list[str]:
        if effective_cwd is None:
            effective_cwd = self.worktree_root
        if lexical_cwds is None:
            lexical_cwds = [effective_cwd]

        exe = Path(tokens[0]).name
        exe_lower = exe.lower()

        if exe_lower == "git":
            self._validate_git(tokens[1:], command, effective_cwd)

        # Restrict inline code execution flags and `-m <module>` for python across all roles
        python_module: str | None = None
        python_module_end_idx: int | None = None
        cov_nested_module: str | None = None
        cov_nested_end_idx: int | None = None
        if exe_lower == "python" or exe_lower.startswith("python3") or exe_lower.startswith("python2"):
            skip_next_py = False
            expect_py_x = False
            expect_py_module = False

            def _validate_python_x_opt(x_val: str) -> None:
                if x_val.lower().startswith("pycache_prefix="):
                    if self.readonly:
                        raise ScopeViolationError(
                            self.role,
                            "shell",
                            command,
                            "Read-only role cannot set Python '-X pycache_prefix'",
                        )
                    prefix_path = x_val.split("=", 1)[1]
                    if not prefix_path.strip():
                        raise ScopeViolationError(
                            self.role,
                            "shell",
                            command,
                            "Empty path for Python '-X pycache_prefix'",
                        )
                    self.enforce_write(prefix_path, base_dir=effective_cwd)

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
                if expect_py_x:
                    expect_py_x = False
                    _validate_python_x_opt(tok)
                    continue
                if skip_next_py:
                    skip_next_py = False
                    continue
                if tok == "--":
                    break
                if tok == "-X":
                    expect_py_x = True
                    continue
                if tok in ("-W", "--check-hash-based-pycs"):
                    skip_next_py = True
                    continue
                if tok.startswith("-X") and not tok.startswith("--"):
                    _validate_python_x_opt(tok[2:])
                    continue
                if tok.startswith("-W") and not tok.startswith("--"):
                    continue
                if not tok.startswith("-"):
                    break
                if not tok.startswith("--"):
                    short_chars = tok[1:]
                    for c_pos, ch in enumerate(short_chars):
                        if ch == "c":
                            raise ScopeViolationError(
                                self.role,
                                "shell",
                                command,
                                "Inline 'python -c' code execution is disallowed",
                            )
                        if ch == "X":
                            x_rest = short_chars[c_pos + 1 :]
                            if x_rest:
                                _validate_python_x_opt(x_rest)
                            else:
                                expect_py_x = True
                            break
                        if ch == "W":
                            w_rest = short_chars[c_pos + 1 :]
                            if not w_rest:
                                skip_next_py = True
                            break
                        if ch == "m":
                            mod_rest = short_chars[c_pos + 1 :]
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
                            else:
                                expect_py_module = True
                            break
                    if python_module is not None:
                        break
            if expect_py_x:
                raise ScopeViolationError(
                    self.role,
                    "shell",
                    command,
                    "Missing value for Python '-X' flag",
                )
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
        pytest_start_idx: int | None = None
        if is_pytest and not in_pytest_addopts:
            if exe_lower == "pytest":
                pytest_start_idx = 1
            elif python_module == "pytest" and python_module_end_idx is not None:
                pytest_start_idx = python_module_end_idx + 1
            elif cov_nested_module == "pytest" and cov_nested_end_idx is not None:
                pytest_start_idx = cov_nested_end_idx + 1
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
            for idx, t in enumerate(tokens[1:], start=1):
                in_cov_prefix = (
                    is_coverage
                    and python_module_end_idx is not None
                    and idx > python_module_end_idx
                    and (cov_nested_end_idx is None or idx <= cov_nested_end_idx)
                )
                t_flag = t.split("=", 1)[0]
                if (
                    t_flag in _FILE_WRITING_FLAGS
                    or t == "--ext-diff"
                    or t.startswith("--ext-diff=")
                    or t == "-o"
                    or (t.startswith("-o") and not t.startswith("--"))
                    or (
                        is_pytest
                        and not in_cov_prefix
                        and (
                            t == "--override-ini"
                            or t.startswith("--override-ini=")
                            or t == "--debug"
                            or t.startswith("--debug=")
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
        expect_pytest_cfg = False
        expect_pytest_rootdir = False
        expect_pytest_p = False
        expect_pytest_p_can_disable = False
        has_explicit_pytest_cfg = False
        has_explicit_pytest_cache_dir = False
        has_explicit_pytest_rootdir = False
        has_no_cacheprovider = False
        pytest_positional_args: list[str] = []
        expect_pytest_flag_val = False
        pytest_after_double_dash = False

        for idx, tok in enumerate(tokens[1:], start=1):
            in_cov_prefix = (
                is_coverage
                and python_module_end_idx is not None
                and idx > python_module_end_idx
                and (cov_nested_end_idx is None or idx <= cov_nested_end_idx)
            )
            cov_flag_active = in_cov_prefix or (is_coverage and cov_nested_module is None)

            in_pytest_arg_scope = (
                (pytest_start_idx is not None and idx >= pytest_start_idx)
                or (is_pytest and in_pytest_addopts)
            )
            if in_pytest_arg_scope and tok.startswith("@"):
                raise ScopeViolationError(
                    self.role,
                    "shell",
                    command,
                    "Pytest '@argsfile' expansion is disallowed by Thread role policy",
                )

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
                self.enforce_write(tok, base_dir=effective_cwd)
                continue

            if expect_pytest_ini:
                expect_pytest_ini = False
                if self._check_pytest_override_ini(
                    tok,
                    command,
                    in_pytest_addopts=in_pytest_addopts,
                    effective_cwd=effective_cwd,
                    lexical_cwds=lexical_cwds,
                ):
                    has_explicit_pytest_cache_dir = True
                continue

            if expect_pytest_cfg:
                expect_pytest_cfg = False
                self._validate_pytest_config_file(
                    tok,
                    command,
                    base_dir=effective_cwd,
                    effective_cwd=effective_cwd,
                    lexical_cwds=lexical_cwds,
                )
                continue

            if expect_pytest_rootdir:
                expect_pytest_rootdir = False
                self._validate_pytest_rootdir(tok, command, base_dir=effective_cwd)
                continue

            in_pytest_section = pytest_start_idx is not None and idx >= pytest_start_idx
            if in_pytest_section and expect_pytest_flag_val:
                expect_pytest_flag_val = False
                if expect_pytest_p:
                    expect_pytest_p = False
                    if expect_pytest_p_can_disable and tok == "no:cacheprovider":
                        has_no_cacheprovider = True
                    elif tok == "cacheprovider":
                        has_no_cacheprovider = False
                    expect_pytest_p_can_disable = False
            elif in_pytest_section:
                if tok == "-p":
                    expect_pytest_flag_val = True
                    expect_pytest_p = True
                    expect_pytest_p_can_disable = not pytest_after_double_dash
                elif tok.startswith("-p") and not tok.startswith("--") and len(tok) > 2:
                    if not pytest_after_double_dash and tok[2:] == "no:cacheprovider":
                        has_no_cacheprovider = True
                    elif tok[2:] == "cacheprovider":
                        has_no_cacheprovider = False
                elif not tok.startswith("--") and len(tok) > 2 and _parse_bundled_pytest_p(tok)[0]:
                    _, bundled_p = _parse_bundled_pytest_p(tok)
                    if bundled_p is None:
                        expect_pytest_flag_val = True
                        expect_pytest_p = True
                        expect_pytest_p_can_disable = False
                    elif bundled_p == "cacheprovider":
                        has_no_cacheprovider = False
                elif pytest_after_double_dash:
                    pytest_positional_args.append(tok)
                elif tok == "--":
                    pytest_after_double_dash = True
                elif not tok.startswith("-"):
                    pytest_positional_args.append(tok)
                elif tok in ("-c", "--config-file") or tok.startswith("--config-file="):
                    has_explicit_pytest_cfg = True
                elif not tok.startswith("--") and len(tok) > 2 and _parse_bundled_pytest_c(tok)[0]:
                    has_explicit_pytest_cfg = True
                elif tok in _PYTEST_VALUE_LONG_FLAGS or _pytest_short_flag_expects_next_value(tok):
                    expect_pytest_flag_val = True

            if is_pytest and not in_cov_prefix and (tok == "--debug" or tok.startswith("--debug=")):
                raise ScopeViolationError(
                    self.role,
                    "shell",
                    command,
                    f"Pytest flag {tok.split('=', 1)[0]!r} is disallowed",
                )

            if is_pytest and not in_cov_prefix and tok in ("-c", "--config-file"):
                expect_pytest_cfg = True
                continue

            if is_pytest and not in_cov_prefix and tok == "--rootdir":
                has_explicit_pytest_rootdir = True
                expect_pytest_rootdir = True
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
                # Bundled / glued pytest `-o` and `-c` clusters (`-qo`, `-vc<path>`, `-qc=<path>`)
                # must be checked BEFORE `if "=" in tok:` and before falling through to `tok[2:]`.
                if (
                    is_pytest
                    and not in_cov_prefix
                    and not tok.startswith("--")
                    and len(tok) > 2
                ):
                    found_c, attached_c, empty_c_eq = _parse_bundled_pytest_c(tok)
                    if found_c:
                        if empty_c_eq:
                            raise ScopeViolationError(
                                self.role,
                                "shell",
                                command,
                                "Missing path for pytest '-c' flag",
                            )
                        if attached_c is None:
                            expect_pytest_cfg = True
                        else:
                            self._validate_pytest_config_file(
                                attached_c,
                                command,
                                base_dir=effective_cwd,
                                effective_cwd=effective_cwd,
                                lexical_cwds=lexical_cwds,
                            )
                        continue
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
                            if self._check_pytest_override_ini(
                                attached_o,
                                command,
                                in_pytest_addopts=in_pytest_addopts,
                                effective_cwd=effective_cwd,
                                lexical_cwds=lexical_cwds,
                            ):
                                has_explicit_pytest_cache_dir = True
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
                        if self._check_pytest_override_ini(
                            attached,
                            command,
                            in_pytest_addopts=in_pytest_addopts,
                            effective_cwd=effective_cwd,
                            lexical_cwds=lexical_cwds,
                        ):
                            has_explicit_pytest_cache_dir = True
                    else:
                        if self.readonly:
                            raise ScopeViolationError(
                                self.role,
                                "shell",
                                command,
                                "Read-only role cannot use file-writing flag '-o'",
                            )
                        self.enforce_write(attached, base_dir=effective_cwd)
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
                    self.enforce_write(tok[2:], base_dir=effective_cwd)
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
                        self.enforce_write(flag_val, base_dir=effective_cwd)
                        continue
                    if is_pytest and flag_name in ("--override-ini", "-o"):
                        if self.readonly:
                            raise ScopeViolationError(
                                self.role,
                                "shell",
                                command,
                                f"Read-only role cannot override pytest ini via {flag_name!r}",
                            )
                        if self._check_pytest_override_ini(
                            flag_val,
                            command,
                            in_pytest_addopts=in_pytest_addopts,
                            effective_cwd=effective_cwd,
                            lexical_cwds=lexical_cwds,
                        ):
                            has_explicit_pytest_cache_dir = True
                        continue
                    if is_pytest and not in_cov_prefix and flag_name == "--config-file":
                        self._validate_pytest_config_file(
                            flag_val,
                            command,
                            base_dir=effective_cwd,
                            effective_cwd=effective_cwd,
                            lexical_cwds=lexical_cwds,
                        )
                        continue
                    if is_pytest and not in_cov_prefix and flag_name == "--rootdir":
                        has_explicit_pytest_rootdir = True
                        self._validate_pytest_rootdir(flag_val, command, base_dir=effective_cwd)
                        continue
                    candidates = [flag_val]
                    if ":" in flag_val and not (len(flag_val) >= 2 and flag_val[1] == ":"):
                        candidates.extend(seg for seg in flag_val.split(":") if seg)
                    for cand in candidates:
                        if "/" in cand or "\\" in cand or ".." in cand or Path(cand).is_absolute():
                            file_part = cand.split("::", 1)[0]
                            if file_part:
                                self._resolve_and_check_containment(
                                    file_part, "read", base_dir=effective_cwd
                                )
                elif len(tok) > 2 and not tok.startswith("--"):
                    attached = tok[2:]
                    if "/" in attached or "\\" in attached or ".." in attached:
                        file_part = attached.split("::", 1)[0]
                        if file_part:
                            self._resolve_and_check_containment(
                                file_part, "read", base_dir=effective_cwd
                            )
                continue

            if "/" in tok or "\\" in tok or ".." in tok or Path(tok).is_absolute():
                # Allow pytest nodeids like tests/test_a.py::test_fn by stripping ::nodeid
                file_part = tok.split("::", 1)[0]
                if file_part:
                    self._resolve_and_check_containment(
                        file_part, "read", base_dir=effective_cwd
                    )

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
        if expect_pytest_cfg:
            raise ScopeViolationError(
                self.role,
                "shell",
                command,
                "Missing path for pytest '-c'/'--config-file' flag",
            )
        if expect_pytest_rootdir:
            raise ScopeViolationError(
                self.role,
                "shell",
                command,
                "Missing path for pytest '--rootdir' flag",
            )

        if is_pytest and not in_pytest_addopts and not has_explicit_pytest_cfg:
            self._validate_pytest_implicit_configs(
                pytest_positional_args,
                command,
                effective_cwd=effective_cwd,
                lexical_cwds=lexical_cwds,
                has_explicit_cache_dir=has_explicit_pytest_cache_dir,
                has_explicit_rootdir=has_explicit_pytest_rootdir,
                has_no_cacheprovider=has_no_cacheprovider,
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
                resolved_target = self.enforce_write(r_target, base_dir=effective_cwd)
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

    def _validate_pytest_rootdir(
        self, rootdir_val: str, command: str, *, base_dir: Path | None = None
    ) -> None:
        raw_rd = rootdir_val.strip()
        if not raw_rd:
            raise ScopeViolationError(
                self.role, "shell", command, "Missing path for pytest '--rootdir' flag"
            )
        resolved_rd, _ = self._resolve_and_check_containment(
            raw_rd, "read", base_dir=base_dir
        )
        if resolved_rd != self.worktree_root:
            raise ScopeViolationError(
                self.role,
                "shell",
                command,
                f"Pytest '--rootdir' {rootdir_val!r} must resolve to worktree root",
            )

    def _validate_pytest_config_options(
        self,
        opts: dict[str, Any],
        command: str,
        cfg: str,
        *,
        effective_cwd: Path | None = None,
        lexical_cwds: list[Path] | None = None,
    ) -> None:
        for raw_key, raw_val in opts.items():
            key_lower = str(raw_key).strip().lower()
            if key_lower not in _PYTEST_INSPECTED_INI_KEYS:
                continue
            if key_lower == "addopts":
                if isinstance(raw_val, str):
                    addopts_str = " ".join(raw_val.replace("\r", "\n").splitlines())
                elif isinstance(raw_val, (list, tuple)):
                    if not all(isinstance(item, str) for item in raw_val):
                        raise ScopeViolationError(
                            self.role,
                            "shell",
                            command,
                            f"Malformed addopts list in pytest config {cfg!r}",
                        )
                    addopts_str = shlex.join(raw_val)
                else:
                    raise ScopeViolationError(
                        self.role,
                        "shell",
                        command,
                        f"Malformed addopts value in pytest config {cfg!r}",
                    )
                self._check_pytest_override_ini(
                    f"addopts={addopts_str}",
                    command,
                    in_pytest_addopts=False,
                    from_config_file=True,
                    effective_cwd=effective_cwd,
                    lexical_cwds=lexical_cwds,
                )
            elif key_lower in ("testpaths", "pythonpath", "norecursedirs") and isinstance(
                raw_val, (list, tuple)
            ):
                if not all(isinstance(item, str) for item in raw_val):
                    raise ScopeViolationError(
                        self.role,
                        "shell",
                        command,
                        f"Malformed {key_lower!r} list in pytest config {cfg!r}",
                    )
                for item in raw_val:
                    self._check_pytest_override_ini(
                        f"{key_lower}={item}",
                        command,
                        in_pytest_addopts=False,
                        from_config_file=True,
                        effective_cwd=effective_cwd,
                        lexical_cwds=lexical_cwds,
                    )
            elif isinstance(raw_val, str):
                self._check_pytest_override_ini(
                    f"{key_lower}={raw_val}",
                    command,
                    in_pytest_addopts=False,
                    from_config_file=True,
                    effective_cwd=effective_cwd,
                    lexical_cwds=lexical_cwds,
                )
            elif raw_val is not None:
                raise ScopeViolationError(
                    self.role,
                    "shell",
                    command,
                    f"Malformed {key_lower!r} value in pytest config {cfg!r}",
                )

    def _is_path_writable(self, candidate: Path) -> bool:
        if self.readonly:
            return False
        try:
            self.enforce_write(candidate)
            return True
        except ScopeViolationError:
            return False

    def _validate_pytest_implicit_configs(
        self,
        positional_args: list[str],
        command: str,
        *,
        effective_cwd: Path | None = None,
        lexical_cwds: list[Path] | None = None,
        has_explicit_cache_dir: bool = False,
        has_explicit_rootdir: bool = False,
        has_no_cacheprovider: bool = False,
    ) -> None:
        if effective_cwd is None:
            effective_cwd = self.worktree_root
        if lexical_cwds is None:
            lexical_cwds = [effective_cwd]

        start_dirs: list[Path] = []
        for cwd_dir in (effective_cwd, *lexical_cwds):
            if cwd_dir != self.worktree_root and cwd_dir not in start_dirs:
                start_dirs.append(cwd_dir)

        anchors: list[Path] = [effective_cwd]
        for lc in lexical_cwds:
            if lc not in anchors:
                anchors.append(lc)

        for raw_arg in positional_args:
            file_part = raw_arg.split("::", 1)[0].strip()
            if not file_part:
                continue
            resolved_pos, _ = self._resolve_and_check_containment(
                file_part, "read", base_dir=effective_cwd
            )
            res_start = resolved_pos if resolved_pos.is_dir() else resolved_pos.parent
            if res_start not in start_dirs:
                start_dirs.append(res_start)

            for lexical_pos in self._compute_lexical_paths(file_part, anchors=anchors):
                lex_start = (
                    lexical_pos
                    if (
                        lexical_pos.exists()
                        and lexical_pos.is_dir()
                        and not lexical_pos.is_symlink()
                    )
                    else lexical_pos.parent
                )
                if lex_start not in start_dirs:
                    start_dirs.append(lex_start)

        checked_dirs: set[Path] = set()
        for start_dir in start_dirs:
            cur = start_dir
            while cur != self.worktree_root and cur.parent != cur:
                try:
                    cur.relative_to(self.worktree_root)
                except ValueError:
                    break
                if cur in checked_dirs:
                    break
                checked_dirs.add(cur)
                if cur.is_symlink() and cur.resolve(strict=False) == self.worktree_root:
                    cur = cur.parent
                    continue
                for cfg_name in _PYTEST_CONFIG_FILENAMES:
                    cand = cur / cfg_name
                    if not (cand.is_symlink() or cand.exists()):
                        continue
                    rel_disp = cand.relative_to(self.worktree_root).as_posix()
                    if cand.is_symlink():
                        raise ScopeViolationError(
                            self.role,
                            "shell",
                            command,
                            f"Symlink pytest config {rel_disp!r} in subdirectory is disallowed",
                        )
                    if cfg_name in ("pytest.toml", ".pytest.toml", "pytest.ini", ".pytest.ini"):
                        raise ScopeViolationError(
                            self.role,
                            "shell",
                            command,
                            f"Implicit subdirectory pytest config {rel_disp!r} is disallowed",
                        )
                    if not cand.is_file():
                        raise ScopeViolationError(
                            self.role,
                            "shell",
                            command,
                            f"Non-regular subdirectory config path {rel_disp!r} is disallowed",
                        )
                    if self._is_path_writable(cand):
                        raise ScopeViolationError(
                            self.role,
                            "shell",
                            command,
                            f"Worker-writable subdirectory config {rel_disp!r} cannot be implicitly loaded by pytest",
                        )
                    if cfg_name == "pyproject.toml":
                        try:
                            data = tomllib.loads(cand.read_text(encoding="utf-8"))
                        except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
                            raise ScopeViolationError(
                                self.role,
                                "shell",
                                command,
                                f"Unreadable or malformed subdirectory config {rel_disp!r}: {exc}",
                            ) from exc
                        tool = data.get("tool")
                        has_pytest = "pytest" in data or (
                            isinstance(tool, dict) and "pytest" in tool
                        )
                        if has_pytest or (tool is not None and not isinstance(tool, dict)):
                            raise ScopeViolationError(
                                self.role,
                                "shell",
                                command,
                                f"Subdirectory pytest config in {rel_disp!r} is disallowed",
                            )
                    else:
                        parser = configparser.RawConfigParser(allow_no_value=True)
                        try:
                            parser.read_string(cand.read_text(encoding="utf-8"))
                        except (OSError, UnicodeDecodeError, configparser.Error) as exc:
                            raise ScopeViolationError(
                                self.role,
                                "shell",
                                command,
                                f"Unreadable or malformed subdirectory config {rel_disp!r}: {exc}",
                            ) from exc
                        if parser.has_section("pytest") or parser.has_section("tool:pytest"):
                            raise ScopeViolationError(
                                self.role,
                                "shell",
                                command,
                                f"Subdirectory pytest config in {rel_disp!r} is disallowed",
                            )
                cur = cur.parent

        has_root_anchoring_config = False
        for cfg_name in _PYTEST_CONFIG_FILENAMES:
            root_cfg = self.worktree_root / cfg_name
            if root_cfg.is_symlink() or root_cfg.exists():
                self._validate_pytest_config_file(
                    cfg_name,
                    command,
                    base_dir=self.worktree_root,
                    effective_cwd=effective_cwd,
                    lexical_cwds=lexical_cwds,
                )
                if root_cfg.is_file():
                    if cfg_name in (
                        "pytest.toml",
                        ".pytest.toml",
                        "pytest.ini",
                        ".pytest.ini",
                        "pyproject.toml",
                    ):
                        has_root_anchoring_config = True
                    elif cfg_name == "tox.ini":
                        parser = configparser.RawConfigParser(allow_no_value=True)
                        try:
                            parser.read_string(root_cfg.read_text(encoding="utf-8"))
                        except (OSError, UnicodeDecodeError, configparser.Error):
                            pass
                        else:
                            if parser.has_section("pytest"):
                                has_root_anchoring_config = True
                    elif cfg_name == "setup.cfg":
                        parser = configparser.RawConfigParser(allow_no_value=True)
                        try:
                            parser.read_string(root_cfg.read_text(encoding="utf-8"))
                        except (OSError, UnicodeDecodeError, configparser.Error):
                            pass
                        else:
                            if parser.has_section("tool:pytest"):
                                has_root_anchoring_config = True

        if (
            not has_root_anchoring_config
            and not has_explicit_cache_dir
            and not has_explicit_rootdir
            and not has_no_cacheprovider
            and effective_cwd != self.worktree_root
        ):
            self.enforce_write(".pytest_cache", base_dir=effective_cwd)

    def _validate_pytest_config_file(
        self,
        cfg: str,
        command: str,
        *,
        base_dir: Path | None = None,
        effective_cwd: Path | None = None,
        lexical_cwds: list[Path] | None = None,
    ) -> None:
        raw_cfg = cfg.strip()
        if not raw_cfg:
            raise ScopeViolationError(
                self.role, "shell", command, "Missing path for pytest config flag"
            )
        anchor = base_dir if base_dir is not None else self.worktree_root
        resolved_cfg, _ = self._resolve_and_check_containment(
            raw_cfg, "read", base_dir=anchor
        )
        local_cfg = raw_cfg
        if "://" in raw_cfg or raw_cfg.lower().startswith("file:"):
            parsed = urlsplit(raw_cfg)
            local_cfg = url2pathname(parsed.path)
        p_raw = Path(local_cfg)
        cand_cfg = Path(os.path.normpath(p_raw if p_raw.is_absolute() else (anchor / p_raw)))
        if cand_cfg.is_symlink():
            raise ScopeViolationError(
                self.role,
                "shell",
                command,
                f"Pytest config path {cfg!r} cannot be a symlink",
            )
        if (
            resolved_cfg.parent != self.worktree_root
            or resolved_cfg.name not in _ALLOWED_PYTEST_ROOT_CONFIGS
        ):
            raise ScopeViolationError(
                self.role,
                "shell",
                command,
                f"Pytest config file {cfg!r} must be a root project config {sorted(_ALLOWED_PYTEST_ROOT_CONFIGS)}",
            )
        if resolved_cfg.exists() and not resolved_cfg.is_file():
            raise ScopeViolationError(
                self.role,
                "shell",
                command,
                f"Pytest config path {cfg!r} is not a regular file",
            )
        if not resolved_cfg.is_file():
            return

        if resolved_cfg.name.endswith(".toml"):
            try:
                data = tomllib.loads(resolved_cfg.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
                raise ScopeViolationError(
                    self.role,
                    "shell",
                    command,
                    f"Unreadable or malformed pytest config {cfg!r}: {exc}",
                ) from exc
            sections_to_check: list[dict[str, Any]] = []
            pytest_root = data.get("pytest")
            if pytest_root is not None:
                if not isinstance(pytest_root, dict):
                    raise ScopeViolationError(
                        self.role, "shell", command, f"Malformed [pytest] table in {cfg!r}"
                    )
                ini_opts = pytest_root.get("ini_options")
                if ini_opts is not None:
                    if not isinstance(ini_opts, dict):
                        raise ScopeViolationError(
                            self.role,
                            "shell",
                            command,
                            f"Malformed [pytest.ini_options] table in {cfg!r}",
                        )
                    sections_to_check.append(ini_opts)
                direct_opts = {k: v for k, v in pytest_root.items() if k != "ini_options"}
                if direct_opts:
                    sections_to_check.append(direct_opts)

            tool = data.get("tool")
            if tool is not None:
                if not isinstance(tool, dict):
                    raise ScopeViolationError(
                        self.role, "shell", command, f"Malformed [tool] table in {cfg!r}"
                    )
                pytest_tbl = tool.get("pytest")
                if pytest_tbl is not None:
                    if not isinstance(pytest_tbl, dict):
                        raise ScopeViolationError(
                            self.role,
                            "shell",
                            command,
                            f"Malformed [tool.pytest] table in {cfg!r}",
                        )
                    ini_opts = pytest_tbl.get("ini_options")
                    if ini_opts is not None:
                        if not isinstance(ini_opts, dict):
                            raise ScopeViolationError(
                                self.role,
                                "shell",
                                command,
                                f"Malformed [tool.pytest.ini_options] table in {cfg!r}",
                            )
                        sections_to_check.append(ini_opts)
                    direct_opts = {k: v for k, v in pytest_tbl.items() if k != "ini_options"}
                    if direct_opts:
                        sections_to_check.append(direct_opts)

            for opts in sections_to_check:
                self._validate_pytest_config_options(
                    opts,
                    command,
                    cfg,
                    effective_cwd=effective_cwd,
                    lexical_cwds=lexical_cwds,
                )
            return

        parser = configparser.RawConfigParser(allow_no_value=True)
        try:
            text = resolved_cfg.read_text(encoding="utf-8")
            parser.read_string(text)
        except (OSError, UnicodeDecodeError, configparser.Error) as exc:
            raise ScopeViolationError(
                self.role,
                "shell",
                command,
                f"Unreadable or malformed pytest config {cfg!r}: {exc}",
            ) from exc

        for sec_name in ("pytest", "tool:pytest"):
            if parser.has_section(sec_name):
                self._validate_pytest_config_options(
                    dict(parser.items(sec_name)),
                    command,
                    cfg,
                    effective_cwd=effective_cwd,
                    lexical_cwds=lexical_cwds,
                )

    def _check_pytest_override_ini(
        self,
        val: str,
        command: str,
        *,
        in_pytest_addopts: bool = False,
        from_config_file: bool = False,
        effective_cwd: Path | None = None,
        lexical_cwds: list[Path] | None = None,
    ) -> bool:
        if effective_cwd is None:
            effective_cwd = self.worktree_root
        if lexical_cwds is None:
            lexical_cwds = [effective_cwd]

        if "=" in val:
            ini_key, ini_val = val.split("=", 1)
            key_lower = ini_key.strip().lower()
            if key_lower == "addopts":
                if self.readonly and not from_config_file:
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
                    return False
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
                    effective_cwd=effective_cwd,
                    lexical_cwds=lexical_cwds,
                )
                return False
            if key_lower in ("log_file", "cache_dir", "basetemp", "resultlog"):
                if self.readonly:
                    raise ScopeViolationError(
                        self.role,
                        "shell",
                        command,
                        f"Read-only role cannot override pytest ini {ini_key!r}",
                    )
                if key_lower == "cache_dir":
                    # Pytest resolves `cache_dir` relative to `rootdir` (`worktree_root` when a
                    # root config exists, or `effective_cwd` otherwise); validate against both.
                    self.enforce_write(ini_val.strip(), base_dir=self.worktree_root)
                    if effective_cwd != self.worktree_root:
                        self.enforce_write(ini_val.strip(), base_dir=effective_cwd)
                    return True
                self.enforce_write(ini_val.strip(), base_dir=effective_cwd)
                return False
            try:
                val_segments = shlex.split(ini_val)
            except ValueError:
                val_segments = ini_val.split()
            for seg in val_segments:
                if (
                    "/" in seg
                    or "\\" in seg
                    or ".." in seg
                    or Path(seg).is_absolute()
                    or "://" in seg
                    or seg.lower().startswith("file:")
                ):
                    self._resolve_and_check_containment(
                        seg, "read", base_dir=self.worktree_root
                    )
                    if not from_config_file and effective_cwd != self.worktree_root:
                        self._resolve_and_check_containment(
                            seg, "read", base_dir=effective_cwd
                        )
        return False

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

    def _extract_and_validate_cwds(
        self, args: Any, label: str
    ) -> tuple[str | None, Path, list[Path]]:
        """Recursively scan nested dicts/lists for _SHELL_CWD_KEYS and validate containment."""
        found: list[tuple[str, Path]] = []

        def _walk(node: Any) -> None:
            if isinstance(node, Mapping):
                has_cwd = any(k in node and node[k] is not None for k in _SHELL_CWD_KEYS)
                if has_cwd:
                    cwd_val = self._validate_shell_cwd_mapping(dict(node), label)
                    if cwd_val is not None:
                        resolved, _ = self._resolve_shell_cwd(cwd_val, label)
                        found.append((cwd_val, resolved))
                for val in node.values():
                    if isinstance(val, (Mapping, list, tuple)):
                        _walk(val)
            elif isinstance(node, (list, tuple)):
                for item in node:
                    if isinstance(item, (Mapping, list, tuple)):
                        _walk(item)

        _walk(args)
        if not found:
            return None, self.worktree_root, [self.worktree_root]

        first_resolved = found[0][1]
        for _, resolved in found[1:]:
            if resolved != first_resolved:
                raise ScopeViolationError(
                    self.role,
                    "shell",
                    label,
                    "Conflicting working directory values across tool arguments",
                )

        chosen_raw = found[0][0]
        for raw_val, resolved in found:
            lex_paths = self._compute_lexical_paths(raw_val)
            if any(lp != resolved for lp in lex_paths):
                chosen_raw = raw_val
                break
        resolved_cwd, _ = self._resolve_shell_cwd(chosen_raw, label)
        return chosen_raw, resolved_cwd, [resolved_cwd]

    def _extract_shell_command_values(self, args: Any, tool_name: str) -> list[str]:
        """Recursively collect and fail-closed validate all present non-None _SHELL_CMD_KEYS."""
        commands: list[str] = []

        def _walk(node: Any) -> None:
            if isinstance(node, Mapping):
                for key in _SHELL_CMD_KEYS:
                    if key in node and node[key] is not None:
                        val = node[key]
                        if not isinstance(val, str) or not val.strip():
                            raise ScopeViolationError(
                                self.role,
                                "tool",
                                tool_name,
                                f"Invalid or empty shell command argument {key!r} (fail closed)",
                            )
                        commands.append(val)
                for val in node.values():
                    if isinstance(val, (Mapping, list, tuple)):
                        _walk(val)
            elif isinstance(node, (list, tuple)):
                for item in node:
                    if isinstance(item, (Mapping, list, tuple)):
                        _walk(item)

        _walk(args)
        return commands

    def enforce_tool_call(
        self, tool_name: str, tool_args: dict[str, Any] | str | None
    ) -> None:
        """Fail-closed validation of an agent tool invocation prior to execution."""
        if not isinstance(tool_name, str) or not tool_name.strip():
            raise ScopeViolationError(
                self.role,
                "tool",
                "<unknown>",
                "Tool call missing toolName (fail closed)",
            )
        norm_name = tool_name.strip().lower()
        args: dict[str, Any]
        if tool_args is None:
            args = {}
        elif isinstance(tool_args, str):
            stripped_args = tool_args.strip()
            try:
                parsed = json.loads(tool_args)
            except json.JSONDecodeError:
                if stripped_args.startswith(("{", "[")):
                    raise ScopeViolationError(
                        self.role,
                        "tool",
                        tool_name,
                        "Malformed JSON toolArgs payload (fail closed)",
                    )
                args = {"raw": tool_args}
            else:
                if isinstance(parsed, dict):
                    args = parsed
                elif isinstance(parsed, str):
                    if parsed.strip().startswith(("{", "[")):
                        raise ScopeViolationError(
                            self.role,
                            "tool",
                            tool_name,
                            "Double-encoded JSON toolArgs payload is disallowed (fail closed)",
                        )
                    args = {"raw": parsed}
                else:
                    raise ScopeViolationError(
                        self.role,
                        "tool",
                        tool_name,
                        "Malformed JSON toolArgs payload (fail closed)",
                    )
        elif isinstance(tool_args, Mapping):
            args = dict(tool_args)
        else:
            raise ScopeViolationError(
                self.role,
                "tool",
                tool_name,
                f"Malformed toolArgs type {type(tool_args).__name__} (fail closed)",
            )

        name_tokens = _split_tool_name_tokens(tool_name)
        if any(tok in ("merge", "push") for tok in name_tokens):
            raise ScopeViolationError(
                self.role, "tool", tool_name, "Workers are forbidden from merging or pushing"
            )

        if norm_name in _SHELL_TOOLS or any(k in norm_name for k in ("bash", "shell", "exec")):
            cwd_val, _, _ = self._extract_and_validate_cwds(args, tool_name)
            cmd_values = self._extract_shell_command_values(args, tool_name)
            if not cmd_values:
                raw_val = args.get("raw")
                if isinstance(raw_val, str) and raw_val.strip():
                    cmd_values = [raw_val]
            if not cmd_values:
                raise ScopeViolationError(
                    self.role,
                    "tool",
                    tool_name,
                    "Shell tool call missing command argument (fail closed)",
                )
            for cmd_val in cmd_values:
                self.enforce_shell(cmd_val, cwd=cwd_val)
            return

        non_shell_cwd, _, resolved_cwds = self._extract_and_validate_cwds(args, tool_name)

        # Enforce any shell command keys (and raw strings on shell-like tools) BEFORE write/read routing
        shell_cmd_values = self._extract_shell_command_values(args, tool_name)
        for cmd_val in shell_cmd_values:
            self.enforce_shell(cmd_val, cwd=non_shell_cwd)

        is_shell_like = any(tok in _SHELL_NAME_TOKENS for tok in name_tokens) or any(
            k in norm_name for k in ("terminal", "command")
        )
        if is_shell_like and not shell_cmd_values:
            raw_val = args.get("raw")
            if isinstance(raw_val, str):
                if not raw_val.strip():
                    raise ScopeViolationError(
                        self.role,
                        "tool",
                        tool_name,
                        "Shell-like tool call has empty raw command argument (fail closed)",
                    )
                self.enforce_shell(raw_val, cwd=non_shell_cwd)

            else:
                raise ScopeViolationError(
                    self.role, "tool", tool_name, "Shell-like tool call missing command argument"
                )

        is_write_routed = norm_name in _WRITE_TOOLS or (
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
        )
        if is_write_routed:
            extracted = self._extract_tool_paths(args)
            if not extracted:
                raise ScopeViolationError(
                    self.role,
                    "tool",
                    tool_name,
                    "Write/edit tool call missing extractable target path (fail closed)",
                )
            for target in extracted:
                for base_dir in resolved_cwds:
                    self.enforce_write(target, base_dir=base_dir)
                if self.worktree_root not in resolved_cwds:
                    self.enforce_write(target, base_dir=self.worktree_root)
            return

        if norm_name in _READ_TOOLS:
            for target in self._extract_tool_paths(
                args, include_patches=False, extra_keys=_READ_EXTRA_PATH_KEYS
            ):
                for base_dir in resolved_cwds:
                    self.enforce_read(target, base_dir=base_dir)
                if self.worktree_root not in resolved_cwds:
                    self.enforce_read(target, base_dir=self.worktree_root)
            return

        if self.readonly:
            raise ScopeViolationError(
                self.role,
                "tool",
                tool_name,
                f"Read-only role cannot invoke unrecognized or mutating tool {tool_name!r}",
            )

        # Unrecognized tools carrying path args must be strictly validated.
        for target in self._extract_tool_paths(args):
            for base_dir in resolved_cwds:
                self.enforce_write(target, base_dir=base_dir)
            if self.worktree_root not in resolved_cwds:
                self.enforce_write(target, base_dir=self.worktree_root)
        for target in self._extract_tool_paths(
            args, include_patches=False, extra_keys=_READ_EXTRA_PATH_KEYS
        ):
            for base_dir in resolved_cwds:
                self.enforce_read(target, base_dir=base_dir)
            if self.worktree_root not in resolved_cwds:
                self.enforce_read(target, base_dir=self.worktree_root)

    def enforce_hook_payload(self, payload: Any) -> str:
        """Validate a pre-tool-use hook / event payload, forwarding top-level cwd keys.

        Returns the extracted ``tool_name`` if allowed, or raises ``ScopeViolationError``
        (failing closed on malformed, conflicting, or out-of-scope payloads).
        """
        if payload is None:
            raise ScopeViolationError(
                self.role, "tool", "<unknown>", "Missing hook payload (fail closed)"
            )
        is_mapping = isinstance(payload, Mapping)
        if not is_mapping and isinstance(
            payload, (str, bytes, int, float, bool, list, tuple, set)
        ):
            raise ScopeViolationError(
                self.role,
                "tool",
                "<malformed>",
                f"Malformed hook payload type {type(payload).__name__} (fail closed)",
            )

        def _get_field(name: str) -> tuple[bool, Any]:
            if is_mapping:
                if name in payload:
                    return True, payload[name]
                return False, None
            if hasattr(payload, name):
                return True, getattr(payload, name)
            return False, None

        tool_name_entries: list[tuple[str, str]] = []
        for key in ("toolName", "tool_name"):
            present, val = _get_field(key)
            if present and val is not None:
                if not isinstance(val, str):
                    raise ScopeViolationError(
                        self.role,
                        "tool",
                        str(val),
                        f"Invalid {key} type {type(val).__name__} (fail closed)",
                    )
                stripped = val.strip()
                if not stripped:
                    raise ScopeViolationError(
                        self.role,
                        "tool",
                        "<unknown>",
                        f"Empty {key} in hook payload (fail closed)",
                    )
                tool_name_entries.append((key, stripped))

        if not tool_name_entries:
            raise ScopeViolationError(
                self.role,
                "tool",
                "<unknown>",
                "Tool call missing toolName (fail closed)",
            )

        first_name_key, tool_name = tool_name_entries[0]
        for key, val in tool_name_entries[1:]:
            if val != tool_name:
                raise ScopeViolationError(
                    self.role,
                    "tool",
                    tool_name,
                    f"Conflicting tool names between {first_name_key!r} and {key!r}",
                )

        def _normalize_args_value(raw_val: Any, key_name: str) -> dict[str, Any]:
            if isinstance(raw_val, Mapping):
                return dict(raw_val)
            if isinstance(raw_val, str):
                try:
                    parsed = json.loads(raw_val)
                except json.JSONDecodeError:
                    if raw_val.strip().startswith(("{", "[")):
                        raise ScopeViolationError(
                            self.role,
                            "tool",
                            tool_name,
                            f"Malformed JSON {key_name} payload (fail closed)",
                        )
                    return {"raw": raw_val}
                if isinstance(parsed, dict):
                    return dict(parsed)
                if isinstance(parsed, str):
                    if parsed.strip().startswith(("{", "[")):
                        raise ScopeViolationError(
                            self.role,
                            "tool",
                            tool_name,
                            f"Double-encoded JSON {key_name} payload is disallowed (fail closed)",
                        )
                    return {"raw": parsed}
                raise ScopeViolationError(
                    self.role,
                    "tool",
                    tool_name,
                    f"Malformed JSON {key_name} payload (fail closed)",
                )
            raise ScopeViolationError(
                self.role,
                "tool",
                tool_name,
                f"Malformed {key_name} type {type(raw_val).__name__} (fail closed)",
            )

        normalized_args_entries: list[tuple[str, dict[str, Any]]] = []
        for key in ("toolArgs", "tool_args", "args", "arguments", "input", "params", "parameters"):
            present, val = _get_field(key)
            if present and val is not None:
                normalized_args_entries.append((key, _normalize_args_value(val, key)))

        effective_args: dict[str, Any] | None = None
        if normalized_args_entries:
            first_args_key, first_args = normalized_args_entries[0]
            for key, norm_args in normalized_args_entries[1:]:
                if norm_args != first_args:
                    raise ScopeViolationError(
                        self.role,
                        "tool",
                        tool_name,
                        f"Conflicting tool arguments between {first_args_key!r} and {key!r}",
                    )
            effective_args = dict(first_args)

        cmd_label = tool_name
        if effective_args is not None:
            for cmd_k in _SHELL_CMD_KEYS:
                cmd_cand = effective_args.get(cmd_k)
                if isinstance(cmd_cand, str) and cmd_cand.strip():
                    cmd_label = cmd_cand
                    break

        _payload_skip_keys = frozenset(
            {"toolName", "tool_name", "toolArgs", "tool_args", "args", "arguments", "input", "params", "parameters"}
        )

        def _payload_obj_to_cwd_tree(
            obj: Any, seen: set[int], *, is_root: bool = False
        ) -> Any:
            if isinstance(obj, Mapping):
                return {
                    k: _payload_obj_to_cwd_tree(v, seen)
                    for k, v in obj.items()
                    if not (is_root and k in _payload_skip_keys)
                }
            if isinstance(obj, (list, tuple)):
                return [_payload_obj_to_cwd_tree(item, seen) for item in obj]
            if obj is None or isinstance(obj, (str, bytes, int, float, bool, Path)):
                return obj
            obj_id = id(obj)
            if obj_id in seen:
                return None
            seen.add(obj_id)
            out: dict[str, Any] = {}
            for key in _SHELL_CWD_KEYS:
                if hasattr(obj, key):
                    val = getattr(obj, key)
                    if val is not None:
                        out[key] = _payload_obj_to_cwd_tree(val, seen)
            for container_attr in ("options", "params", "context", "metadata", "config", "items"):
                if hasattr(obj, container_attr):
                    val = getattr(obj, container_attr)
                    if val is not None:
                        out[container_attr] = _payload_obj_to_cwd_tree(val, seen)
            return out

        if is_mapping:
            payload_cwd_tree: Any = {
                k: v for k, v in payload.items() if k not in _payload_skip_keys
            }
        else:
            payload_cwd_tree = _payload_obj_to_cwd_tree(payload, set(), is_root=True)

        payload_cwd_str, payload_resolved_cwd, _ = self._extract_and_validate_cwds(
            payload_cwd_tree, cmd_label
        )

        if payload_cwd_str is not None:
            if effective_args is None:
                effective_args = {"cwd": payload_cwd_str}
            else:
                for k in _SHELL_CWD_KEYS:
                    present, v = _get_field(k)
                    if (
                        present
                        and v is not None
                        and k in effective_args
                        and effective_args[k] is not None
                    ):
                        arg_v = effective_args[k]
                        if (
                            not isinstance(arg_v, (str, Path))
                            or str(arg_v).strip() != str(v).strip()
                        ):
                            raise ScopeViolationError(
                                self.role,
                                "shell",
                                str(effective_args.get("command") or cmd_label),
                                f"Conflicting working directory between hook payload and toolArgs for {k!r}",
                            )
                args_cwd_str, args_resolved_cwd, _ = self._extract_and_validate_cwds(
                    effective_args, cmd_label
                )
                if args_cwd_str is not None:
                    if args_resolved_cwd != payload_resolved_cwd:
                        raise ScopeViolationError(
                            self.role,
                            "shell",
                            str(effective_args.get("command") or cmd_label),
                            "Conflicting working directory between hook payload and toolArgs",
                        )
                else:
                    effective_args["cwd"] = payload_cwd_str

        self.enforce_tool_call(tool_name, effective_args)
        return tool_name


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

    try:
        policy.enforce_hook_payload(payload)
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
