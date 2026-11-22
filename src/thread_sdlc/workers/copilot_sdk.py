"""GitHub Copilot SDK WorkerAdapter with pre-write RolePolicy hooks and zero-retry PausedQuota."""

from __future__ import annotations

import asyncio
import importlib
import importlib.util
import os
import shutil
import time
from collections.abc import AsyncIterator, Callable, Mapping
from pathlib import Path
from typing import Any, Literal

from thread_sdlc.governance import redactor
from thread_sdlc.workers.adapter import (
    AdapterProbeResult,
    AdapterUnavailableError,
    BaseWorkerAdapter,
    PausedQuota,
    UsageMetrics,
    WorkerAssignment,
    WorkerEvent,
    WorkerExecutionError,
    is_quota_error,
)
from thread_sdlc.workers.permissions import (
    _PATH_ARG_KEYS,
    _SHELL_CWD_KEYS,
    _SHELL_TOOLS,
    _WRITE_TOOLS,
    RolePolicy,
    ScopeViolationError,
)

_AUTH_ENV_VARS = (
    "COPILOT_GITHUB_TOKEN",
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "GITHUB_COPILOT_TOKEN",
)


def _find_copilot_cli() -> str | None:
    env_cli = os.environ.get("COPILOT_CLI_PATH")
    if env_cli and Path(env_cli).is_file():
        return env_cli
    found = shutil.which("copilot")
    if found:
        return found
    gh_copilot = Path.home() / ".local" / "share" / "gh" / "copilot"
    if gh_copilot.is_file():
        return str(gh_copilot)
    return None


def probe_sdk() -> AdapterProbeResult:
    """Probe Copilot SDK package, runtime CLI binary, and auth availability without blocking."""
    sdk_spec = importlib.util.find_spec("copilot")
    sdk_installed = sdk_spec is not None
    cli_path = _find_copilot_cli()
    cli_found = cli_path is not None
    auth_configured = any(bool(os.environ.get(var)) for var in _AUTH_ENV_VARS)

    if not sdk_installed:
        return AdapterProbeResult(
            adapter_type="sdk",
            available=False,
            sdk_installed=False,
            cli_found=cli_found,
            cli_path=cli_path,
            auth_configured=auth_configured,
            details="github-copilot-sdk (module 'copilot') is not installed.",
            blocking_reason="Install optional extra: uv pip install -e '.[copilot]'",
        )

    if not cli_found and not auth_configured:
        return AdapterProbeResult(
            adapter_type="sdk",
            available=False,
            sdk_installed=True,
            cli_found=False,
            cli_path=None,
            auth_configured=False,
            details="Copilot SDK installed, but Copilot CLI runtime and GitHub auth tokens are absent.",
            blocking_reason="Provision Copilot CLI / COPILOT_CLI_PATH and Copilot Business auth token.",
        )

    return AdapterProbeResult(
        adapter_type="sdk",
        available=True,
        sdk_installed=True,
        cli_found=cli_found,
        cli_path=cli_path,
        auth_configured=auth_configured,
        details="Copilot SDK installed and runtime/auth detected.",
    )


def _extract_attr_or_key(obj: Any, *names: str) -> Any:
    for name in names:
        if isinstance(obj, dict) and name in obj:
            return obj[name]
        if hasattr(obj, name):
            return getattr(obj, name)
    return None


_SHELL_PATH_VALUE_KEYS = ("path", "file_name", "fileName", "resolved_path", "resolvedPath")
_SHELL_PATH_OBJECT_META_KEYS = frozenset(
    (*_SHELL_PATH_VALUE_KEYS, "content", "type")
)


def _extract_shell_paths(
    raw_paths: Any, *, allow_single_object: bool = True
) -> list[str]:
    """Extract non-empty path strings from SDK ``possible_paths`` / ``resolved_paths``."""
    extracted: list[str] = []
    if raw_paths is None:
        return extracted
    if isinstance(raw_paths, str):
        if raw_paths.strip():
            extracted.append(raw_paths.strip())
        return extracted
    if isinstance(raw_paths, dict):
        keys = set(raw_paths.keys())
        if (
            allow_single_object
            and keys
            and keys.issubset(_SHELL_PATH_OBJECT_META_KEYS)
            and any(k in raw_paths for k in _SHELL_PATH_VALUE_KEYS)
        ):
            items: list[Any] = [
                raw_paths[k]
                for k in _SHELL_PATH_VALUE_KEYS
                if k in raw_paths and raw_paths[k] is not None
            ]
        else:
            items = []
            for k, v in raw_paths.items():
                if v is None or (isinstance(v, str) and not v.strip()):
                    if isinstance(k, str) and k.strip():
                        items.append(k)
                else:
                    items.append(v)
    elif isinstance(raw_paths, (list, tuple, set)):
        items = list(raw_paths)
    else:
        items = [raw_paths]

    for item in items:
        if isinstance(item, str):
            if item.strip():
                extracted.append(item.strip())
        elif isinstance(item, (dict, list, tuple, set)):
            extracted.extend(
                _extract_shell_paths(item, allow_single_object=allow_single_object)
            )
        elif item is not None:
            p = _extract_attr_or_key(
                item, "path", "file_name", "fileName", "resolved_path", "resolvedPath"
            )
            if isinstance(p, str) and p.strip():
                extracted.append(p.strip())
    return extracted


class CopilotSdkAdapter(BaseWorkerAdapter):
    """WorkerAdapter backed by ``github-copilot-sdk`` (or injected ``client_factory``)."""

    def __init__(
        self,
        policy: RolePolicy,
        *,
        client_factory: Callable[..., Any] | None = None,
        github_token: str | None = None,
        abort_timeout: float = 1.5,
    ) -> None:
        super().__init__(policy)
        self._client_factory = client_factory
        self._github_token = github_token
        self._abort_timeout = abort_timeout

        self._client: Any = None
        self._session: Any = None
        self._queue: asyncio.Queue[WorkerEvent | None] = asyncio.Queue()
        self._scope_violation: ScopeViolationError | None = None
        self._quota_error: PausedQuota | None = None
        self._exec_error: Exception | None = None
        self._abort_requested = False
        self._send_task: asyncio.Task[Any] | None = None
        self._closed = False
        self._stream_redactor = redactor.StreamRedactor()
        self._delta_buffer = ""
        self._delta_event_type = "assistant.message.delta"
        self.start_count = 0

    def _enqueue_event(
        self, event_type: str, message: str = "", data: dict[str, Any] | None = None
    ) -> None:
        self._queue.put_nowait(self._redact_event(event_type, message, data))

    def _flush_delta_buffer(self) -> None:
        if not self._delta_buffer:
            return
        buffered = self._delta_buffer
        self._delta_buffer = ""
        lines = buffered.splitlines(keepends=True) or [buffered]
        scrubbed = "".join(self._stream_redactor.scrub_line(line) for line in lines)
        self._enqueue_event(
            "assistant_message", scrubbed, {"sdk_type": self._delta_event_type}
        )

    def _finish_stream(self) -> None:
        self._flush_delta_buffer()
        if not self._closed:
            self._closed = True
            self._queue.put_nowait(None)

    def _trigger_abort_background(self) -> None:
        if self._abort_requested:
            return
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self.abort())
        except RuntimeError:
            self._abort_requested = True
            self._finish_stream()

    async def _on_pre_tool_use(
        self, input_data: dict[str, Any] | Any, invocation: Any = None
    ) -> dict[str, Any]:
        try:
            tool_name = self._policy.enforce_hook_payload(input_data)
        except ScopeViolationError as err:
            self._scope_violation = err
            self._enqueue_event(
                "scope_violation",
                str(err),
                {"role": err.role, "operation": err.operation, "target": err.target},
            )
            self._trigger_abort_background()
            return {"permissionDecision": "deny", "permissionDecisionReason": str(err)}

        self._enqueue_event("tool_use", f"Allowed tool {tool_name}", {"tool": tool_name})
        return {"permissionDecision": "allow"}

    async def _on_post_tool_use(
        self, input_data: dict[str, Any] | Any, invocation: Any = None
    ) -> dict[str, Any]:
        return {}

    def _make_permission_result(self, *, approved: bool, reason: str, request: Any) -> Any:
        if not isinstance(request, dict):
            try:
                rpc_mod = importlib.import_module("copilot.generated.rpc")
                if approved:
                    return rpc_mod.PermissionDecisionApproveOnce()
                return rpc_mod.PermissionDecisionDeniedByRules(
                    rules=[rpc_mod.PermissionRule(argument=reason, kind="thread-role-policy")]
                )
            except Exception:
                pass
        if approved:
            return {"kind": "approved"}
        return {"kind": "denied-by-rules", "rules": [reason]}

    def _resolve_request_cwd(self, request: Any, label: str) -> tuple[str | None, Path]:
        """Extract and validate _SHELL_CWD_KEYS on SDK permission requests (dict or object)."""
        if isinstance(request, Mapping):
            cwd_str, resolved_cwd, _ = self._policy._extract_and_validate_cwds(
                request, label
            )
            return cwd_str, resolved_cwd

        def _to_mapping_tree(obj: Any, seen: set[int]) -> Any:
            if isinstance(obj, Mapping):
                return {k: _to_mapping_tree(v, seen) for k, v in obj.items()}
            if isinstance(obj, (list, tuple)):
                return [_to_mapping_tree(item, seen) for item in obj]
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
                        out[key] = _to_mapping_tree(val, seen)
            for container_attr in (
                "options",
                "params",
                "args",
                "toolArgs",
                "tool_args",
                "arguments",
                "input",
                "items",
            ):
                if hasattr(obj, container_attr):
                    val = getattr(obj, container_attr)
                    if val is not None:
                        out[container_attr] = _to_mapping_tree(val, seen)
            return out

        collected = _to_mapping_tree(request, set())
        if not collected:
            return None, self._policy.worktree_root
        cwd_str, resolved_cwd, _ = self._policy._extract_and_validate_cwds(
            collected, label
        )
        return cwd_str, resolved_cwd

    async def _on_permission_request(
        self, request: Any, invocation: Any = None
    ) -> Any:
        raw_kind = _extract_attr_or_key(request, "kind")
        kind = str(getattr(raw_kind, "value", raw_kind) or "").strip().lower()
        op: Literal["write", "read", "shell", "tool"]
        if kind == "write":
            op = "write"
        elif kind == "read":
            op = "read"
        elif kind in ("shell", "commands"):
            op = "shell"
        else:
            op = "tool"
        try:
            req_resolved_cwd = self._policy.worktree_root
            if kind in ("write", "read", "path"):
                _, req_resolved_cwd = self._resolve_request_cwd(request, op)

            # Hoist sandbox bypass / permissive / path-grant checks across ALL permission kinds
            if _extract_attr_or_key(request, "request_sandbox_bypass", "requestSandboxBypass"):
                raise ScopeViolationError(
                    self._policy.role,
                    op,
                    "<sandbox-bypass>",
                    "Sandbox bypass requests are denied by Thread role policy (fail closed)",
                )
            if _extract_attr_or_key(
                request, "request_sandbox_permissive", "requestSandboxPermissive"
            ):
                raise ScopeViolationError(
                    self._policy.role,
                    op,
                    "<sandbox-permissive>",
                    "Permissive sandbox requests are denied by Thread role policy (fail closed)",
                )
            sandbox_grant = _extract_attr_or_key(
                request, "sandbox_path_grant", "sandboxPathGrant"
            )
            if sandbox_grant is not None:
                grant_path = _extract_attr_or_key(sandbox_grant, "path")
                if not isinstance(grant_path, str) or not grant_path.strip():
                    raise ScopeViolationError(
                        self._policy.role,
                        op,
                        "<sandbox-path-grant>",
                        "Sandbox path grant missing target path (fail closed)",
                    )
                grant_access_raw = _extract_attr_or_key(sandbox_grant, "access")
                grant_access = (
                    str(getattr(grant_access_raw, "value", grant_access_raw) or "")
                    .strip()
                    .lower()
                )
                if grant_access == "read":
                    self._policy.enforce_read(grant_path.strip(), base_dir=req_resolved_cwd)
                    if req_resolved_cwd != self._policy.worktree_root:
                        self._policy.enforce_read(
                            grant_path.strip(), base_dir=self._policy.worktree_root
                        )
                else:
                    self._policy.enforce_write(grant_path.strip(), base_dir=req_resolved_cwd)
                    if req_resolved_cwd != self._policy.worktree_root:
                        self._policy.enforce_write(
                            grant_path.strip(), base_dir=self._policy.worktree_root
                        )

            if kind == "write":
                def paths_in(obj: Any) -> list[str]:
                    paths = []
                    for key in _PATH_ARG_KEYS:
                        val = _extract_attr_or_key(obj, key)
                        if val is None:
                            continue
                        if not isinstance(val, str) or not val.strip():
                            raise ScopeViolationError(
                                self._policy.role, "write", key, "Invalid write target path"
                            )
                        paths.append(val.strip())
                    return paths

                targets = paths_in(request)
                edits = _extract_attr_or_key(request, "file_edits", "fileEdits")
                if edits is not None:
                    if not isinstance(edits, (list, tuple)):
                        raise ScopeViolationError(
                            self._policy.role, "write", "file_edits", "Expected an edit list"
                        )
                    for edit in edits:
                        edit_targets = paths_in(edit)
                        for side_name in ("after", "before"):
                            side = _extract_attr_or_key(edit, side_name)
                            if side is not None:
                                side_paths = paths_in(side)
                                if not side_paths:
                                    raise ScopeViolationError(
                                        self._policy.role, "write", side_name, "Edit side missing target path"
                                    )
                                edit_targets.extend(side_paths)
                        if not edit_targets:
                            raise ScopeViolationError(
                                self._policy.role, "write", "file_edits", "Edit missing target path"
                            )
                        targets.extend(edit_targets)

                new_contents = _extract_attr_or_key(request, "new_file_contents", "newFileContents")
                if new_contents is not None and not isinstance(new_contents, str):
                    items = new_contents if isinstance(new_contents, (list, tuple)) else [new_contents]
                    for item in items:
                        item_paths = paths_in(item)
                        if not item_paths:
                            raise ScopeViolationError(
                                self._policy.role, "write", "new_file_contents", "Missing target path"
                            )
                        targets.extend(item_paths)
                if not targets:
                    raise ScopeViolationError(
                        self._policy.role,
                        "write",
                        "<unknown>",
                        "Write permission request missing target path (fail closed)",
                    )
                for target in targets:
                    self._policy.enforce_write(target, base_dir=req_resolved_cwd)
                    if req_resolved_cwd != self._policy.worktree_root:
                        self._policy.enforce_write(target, base_dir=self._policy.worktree_root)
            elif kind in ("shell", "commands"):
                possible_urls_raw = _extract_attr_or_key(
                    request, "possible_urls", "possibleUrls"
                )
                if possible_urls_raw:
                    first_url = (
                        possible_urls_raw[0]
                        if isinstance(possible_urls_raw, (list, tuple)) and possible_urls_raw
                        else possible_urls_raw
                    )
                    target_url = (
                        _extract_attr_or_key(first_url, "url", "uri") or str(first_url)
                    )
                    raise ScopeViolationError(
                        self._policy.role,
                        "shell",
                        str(target_url),
                        "Shell permission requests with external URLs are denied by Thread role policy (fail closed)",
                    )
                cmd = _extract_attr_or_key(
                    request, "full_command_text", "fullCommandText", "command"
                )
                cmd_label = cmd if isinstance(cmd, str) and cmd.strip() else "<unknown>"
                cwd_for_shell, resolved_cwd = self._resolve_request_cwd(
                    request, cmd_label
                )

                has_redir = bool(
                    _extract_attr_or_key(
                        request, "has_write_file_redirection", "hasWriteFileRedirection"
                    )
                )
                possible_paths_raw = _extract_attr_or_key(
                    request, "possible_paths", "possiblePaths"
                )
                resolved_paths_raw = _extract_attr_or_key(
                    request, "resolved_paths", "resolvedPaths"
                )
                shell_paths = _extract_shell_paths(possible_paths_raw) + _extract_shell_paths(
                    resolved_paths_raw, allow_single_object=False
                )
                if has_redir:
                    if self._policy.readonly:
                        raise ScopeViolationError(
                            self._policy.role,
                            "shell",
                            "<redirection>",
                            "Read-only role cannot execute shell commands with write file redirection (fail closed)",
                        )
                    if not shell_paths:
                        raise ScopeViolationError(
                            self._policy.role,
                            "shell",
                            "<redirection>",
                            "Shell write file redirection missing verifiable target paths (fail closed)",
                        )
                    for sp in shell_paths:
                        self._policy.enforce_write(sp, base_dir=resolved_cwd)
                else:
                    for sp in shell_paths:
                        self._policy.enforce_read(sp, base_dir=resolved_cwd)
                if not isinstance(cmd, str) or not cmd.strip():
                    raise ScopeViolationError(
                        self._policy.role,
                        "shell",
                        "<unknown>",
                        f"{kind!r} permission request missing command text (fail closed)",
                    )
                self._policy.enforce_shell(cmd, cwd=cwd_for_shell)
            elif kind == "read":
                read_targets: list[str] = []
                for attr in ("file_name", "fileName", "path", "resolved_path", "resolvedPath"):
                    val = _extract_attr_or_key(request, attr)
                    if isinstance(val, str) and val.strip():
                        read_targets.append(val.strip())
                if not read_targets:
                    raise ScopeViolationError(
                        self._policy.role,
                        "read",
                        "<unknown>",
                        "Read permission request missing target path (fail closed)",
                    )
                for target in read_targets:
                    self._policy.enforce_read(target, base_dir=req_resolved_cwd)
                    if req_resolved_cwd != self._policy.worktree_root:
                        self._policy.enforce_read(target, base_dir=self._policy.worktree_root)
            elif kind == "path":
                access_raw = _extract_attr_or_key(request, "access_kind", "accessKind")
                access_kind = str(getattr(access_raw, "value", access_raw) or "").strip().lower()
                ro_dirs = _extract_attr_or_key(
                    request, "read_only_directories", "readOnlyDirectories"
                )
                if isinstance(ro_dirs, (list, tuple)):
                    for ro_dir in ro_dirs:
                        if isinstance(ro_dir, str) and ro_dir.strip():
                            self._policy.enforce_read(ro_dir.strip(), base_dir=req_resolved_cwd)
                            if req_resolved_cwd != self._policy.worktree_root:
                                self._policy.enforce_read(
                                    ro_dir.strip(), base_dir=self._policy.worktree_root
                                )
                paths_raw = _extract_attr_or_key(request, "paths", "path")
                path_list: list[str]
                if isinstance(paths_raw, str):
                    path_list = [paths_raw.strip()] if paths_raw.strip() else []
                elif isinstance(paths_raw, (list, tuple)):
                    path_list = [
                        p.strip() for p in paths_raw if isinstance(p, str) and p.strip()
                    ]
                    if len(path_list) != len(paths_raw):
                        raise ScopeViolationError(
                            self._policy.role,
                            "tool",
                            "<invalid>",
                            "Path permission request contains invalid path entries (fail closed)",
                        )
                else:
                    path_list = []
                if not path_list:
                    raise ScopeViolationError(
                        self._policy.role,
                        "tool",
                        "<unknown>",
                        "Path permission request missing target paths (fail closed)",
                    )
                if access_kind in ("write", "create", "delete", "modify"):
                    for target in path_list:
                        self._policy.enforce_write(target, base_dir=req_resolved_cwd)
                        if req_resolved_cwd != self._policy.worktree_root:
                            self._policy.enforce_write(target, base_dir=self._policy.worktree_root)
                elif access_kind == "read":
                    for target in path_list:
                        self._policy.enforce_read(target, base_dir=req_resolved_cwd)
                        if req_resolved_cwd != self._policy.worktree_root:
                            self._policy.enforce_read(target, base_dir=self._policy.worktree_root)
                else:
                    raise ScopeViolationError(
                        self._policy.role,
                        "tool",
                        ", ".join(path_list),
                        f"Unsupported path permission access_kind {access_kind!r} (fail closed)",
                    )
            elif kind in ("mcp", "custom-tool", "hook"):
                tool_name = _extract_attr_or_key(request, "tool_name", "toolName")
                if not isinstance(tool_name, str) or not tool_name.strip():
                    raise ScopeViolationError(
                        self._policy.role,
                        "tool",
                        kind,
                        f"SDK permission request {kind!r} missing tool_name (fail closed)",
                    )
                self._policy.enforce_hook_payload(request)
            elif kind == "url":
                url = _extract_attr_or_key(request, "url", "uri") or "<unknown>"
                raise ScopeViolationError(
                    self._policy.role,
                    "tool",
                    str(url),
                    "External URL permission requests are denied by Thread role policy (fail closed)",
                )
            else:
                raise ScopeViolationError(
                    self._policy.role,
                    "tool",
                    kind or "<unknown>",
                    f"SDK permission request kind {kind!r} is denied by Thread role policy (fail closed)",
                )
        except ScopeViolationError as err:
            self._scope_violation = err
            self._enqueue_event(
                "scope_violation",
                str(err),
                {"role": err.role, "operation": err.operation, "target": err.target},
            )
            self._trigger_abort_background()
            return self._make_permission_result(approved=False, reason=str(err), request=request)

        return self._make_permission_result(approved=True, reason="allowed", request=request)

    def _handle_sdk_event(self, event: Any) -> None:
        raw_type = _extract_attr_or_key(event, "type")
        if hasattr(raw_type, "value"):
            event_type = str(raw_type.value)
        elif hasattr(raw_type, "name"):
            event_type = str(raw_type.name).lower()
        else:
            event_type = str(raw_type or "")

        data = _extract_attr_or_key(event, "data") or {}
        norm = event_type.lower().replace("_", ".")

        if norm == "assistant.message.delta":
            content = str(
                _extract_attr_or_key(data, "delta_content", "deltaContent", "content") or ""
            )
            self._delta_event_type = event_type
            if content:
                self._delta_buffer += content
                last_nl = self._delta_buffer.rfind("\n")
                if last_nl != -1:
                    complete = self._delta_buffer[: last_nl + 1]
                    self._delta_buffer = self._delta_buffer[last_nl + 1 :]
                    lines = complete.splitlines(keepends=True)
                    scrubbed = "".join(self._stream_redactor.scrub_line(line) for line in lines)
                    self._enqueue_event("assistant_message", scrubbed, {"sdk_type": event_type})
                if self._delta_buffer and self._stream_redactor._in_pem_block:
                    end_match = redactor._PEM_END_LINE_RE.search(self._delta_buffer)
                    if end_match is not None:
                        pem_end_part = self._delta_buffer[: end_match.end()]
                        self._delta_buffer = self._delta_buffer[end_match.end() :]
                        scrubbed = self._stream_redactor.scrub_line(pem_end_part)
                        self._enqueue_event(
                            "assistant_message", scrubbed, {"sdk_type": event_type}
                        )
            return

        if norm == "assistant.message":
            self._flush_delta_buffer()
            content = str(
                _extract_attr_or_key(data, "delta_content", "deltaContent", "content") or ""
            )
            if content:
                lines = content.splitlines(keepends=True) or [content]
                content = "".join(self._stream_redactor.scrub_line(line) for line in lines)
            self._enqueue_event("assistant_message", content, {"sdk_type": event_type})
            return

        if norm == "assistant.usage":
            in_tok = int(_extract_attr_or_key(data, "input_tokens", "inputTokens") or 0)
            out_tok = int(_extract_attr_or_key(data, "output_tokens", "outputTokens") or 0)
            cost = _extract_attr_or_key(data, "cost")
            model = _extract_attr_or_key(data, "model")
            self._usage.input_tokens += in_tok
            self._usage.output_tokens += out_tok
            self._usage.turns_used += 1
            self._usage.credits_used += float(cost) if cost is not None else 1.0
            if isinstance(model, str) and model:
                self._usage.model = model
            self._enqueue_event(
                "usage",
                "Usage recorded",
                {
                    "turns_used": self._usage.turns_used,
                    "credits_used": self._usage.credits_used,
                    "input_tokens": self._usage.input_tokens,
                    "output_tokens": self._usage.output_tokens,
                },
            )
            if self._assignment is not None:
                try:
                    self._check_caps(self._assignment, self._usage)
                except PausedQuota as pq:
                    self._quota_error = pq
                    self._enqueue_event("paused_quota", str(pq), {"limit_type": pq.limit_type})
                    self._trigger_abort_background()
            return

        if norm == "session.error":
            self._flush_delta_buffer()
            err_msg = str(_extract_attr_or_key(data, "message", "error") or "SDK session error")
            if is_quota_error(err_msg):
                pq = PausedQuota(
                    err_msg,
                    limit_type="provider_quota",
                    credits_used=self._usage.credits_used,
                    turns_used=self._usage.turns_used,
                )
                self._quota_error = pq
                self._enqueue_event("paused_quota", err_msg, {"limit_type": "provider_quota"})
                self._trigger_abort_background()
            else:
                self._exec_error = WorkerExecutionError(err_msg)
                self._enqueue_event("error", err_msg)
                self._finish_stream()
            return

        if norm in ("session.idle", "abort"):
            self._flush_delta_buffer()
            if norm == "abort":
                self._usage.aborted = True
                self._enqueue_event("aborted", "SDK session aborted")
            else:
                self._enqueue_event("session_idle", "SDK session idle")
            self._finish_stream()
            return

        self._enqueue_event(norm or "sdk_event", str(_extract_attr_or_key(data, "message") or ""))

    async def start(self, assignment: WorkerAssignment) -> None:
        self.start_count += 1
        self._assignment = assignment
        self._started_at_mono = time.monotonic()
        self._usage = UsageMetrics(model=assignment.model)
        self._queue = asyncio.Queue()
        self._scope_violation = None
        self._quota_error = None
        self._exec_error = None
        self._abort_requested = False
        self._closed = False
        self._stream_redactor = redactor.StreamRedactor()
        self._delta_buffer = ""
        self._delta_event_type = "assistant.message.delta"

        if self._client_factory is not None:
            self._client = self._client_factory()
        else:
            probe = probe_sdk()
            if not probe.available:
                raise AdapterUnavailableError(probe.blocking_reason or probe.details)
            copilot_mod = importlib.import_module("copilot")
            client_kwargs: dict[str, Any] = {"working_directory": str(assignment.worktree_path)}
            if self._github_token:
                client_kwargs["github_token"] = self._github_token
            self._client = copilot_mod.CopilotClient(**client_kwargs)

        if hasattr(self._client, "start"):
            await self._client.start()

        excluded_tools: list[str] | None = None
        if self._policy.readonly:
            excluded_tools = sorted(_WRITE_TOOLS)
            if not self._policy.allowed_shell_prefixes:
                excluded_tools.extend(sorted(_SHELL_TOOLS))

        session_kwargs: dict[str, Any] = {
            "working_directory": str(assignment.worktree_path),
            "on_permission_request": self._on_permission_request,
            "hooks": {
                "on_pre_tool_use": self._on_pre_tool_use,
                "on_post_tool_use": self._on_post_tool_use,
            },
            "streaming": True,
        }
        if assignment.model:
            session_kwargs["model"] = assignment.model
        if excluded_tools is not None:
            session_kwargs["excluded_tools"] = excluded_tools

        self._session = await self._client.create_session(**session_kwargs)
        self._session.on(self._handle_sdk_event)
        self._enqueue_event(
            "session_start",
            f"Started Copilot SDK session for {assignment.ticket_id}",
            {"assignment_id": assignment.assignment_id},
        )

        if hasattr(self._session, "send_and_wait") or hasattr(self._session, "send"):
            self._send_task = asyncio.create_task(
                self._run_send(assignment.instructions, timeout=assignment.timeout_seconds)
            )

    async def _run_send(self, prompt: str, *, timeout: float = 600.0) -> None:
        try:
            if hasattr(self._session, "send_and_wait"):
                await self._session.send_and_wait(prompt, timeout=timeout)
                if not self._closed:
                    self._finish_stream()
            else:
                await self._session.send(prompt)
        except asyncio.CancelledError:
            pass
        except PausedQuota as pq:
            self._quota_error = pq
            self._finish_stream()
        except ScopeViolationError as err:
            self._scope_violation = err
            self._finish_stream()
        except Exception as exc:
            if is_quota_error(str(exc)):
                self._quota_error = PausedQuota(
                    str(exc),
                    limit_type="provider_quota",
                    credits_used=self._usage.credits_used,
                    turns_used=self._usage.turns_used,
                )
            else:
                self._exec_error = WorkerExecutionError(str(exc))
            self._finish_stream()

    async def stream_events(self) -> AsyncIterator[WorkerEvent]:
        while True:
            item = await self._queue.get()
            if item is None:
                break
            yield item

        if self._send_task is not None and not self._send_task.done():
            try:
                await asyncio.wait_for(self._send_task, timeout=0.5)
            except TimeoutError:
                self._send_task.cancel()

        if self._scope_violation is not None:
            raise self._scope_violation
        if self._quota_error is not None:
            raise self._quota_error
        if self._exec_error is not None:
            raise self._exec_error

    async def abort(self) -> None:
        self._abort_requested = True
        self._usage.aborted = True
        if self._session is not None and hasattr(self._session, "abort"):
            try:
                await asyncio.wait_for(self._session.abort(), timeout=self._abort_timeout)
            except Exception:
                pass
        if self._send_task is not None and not self._send_task.done():
            self._send_task.cancel()
        if self._started_at_mono is not None:
            self._usage.duration_ms = (time.monotonic() - self._started_at_mono) * 1000.0
        self._flush_delta_buffer()
        self._enqueue_event("aborted", "Copilot SDK session aborted")
        self._finish_stream()

    async def disconnect(self) -> None:
        if self._send_task is not None and not self._send_task.done():
            self._send_task.cancel()
        if self._session is not None and hasattr(self._session, "disconnect"):
            try:
                await asyncio.wait_for(self._session.disconnect(), timeout=1.5)
            except Exception:
                pass
        if self._client is not None and hasattr(self._client, "stop"):
            try:
                await asyncio.wait_for(self._client.stop(), timeout=1.5)
            except Exception:
                pass
        self._finish_stream()
        if self._started_at_mono is not None:
            self._usage.duration_ms = (time.monotonic() - self._started_at_mono) * 1000.0
