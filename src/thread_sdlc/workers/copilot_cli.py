"""GitHub Copilot CLI subprocess WorkerAdapter with preToolUse hook, redaction, and <2s PGID abort."""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import signal
import sys
import tempfile
import time
from collections.abc import AsyncIterator, Callable
from pathlib import Path
from typing import Any

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
from thread_sdlc.workers.permissions import RolePolicy, ScopeViolationError

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


def probe_cli() -> AdapterProbeResult:
    """Probe Copilot CLI binary and auth tokens without triggering interactive prompts."""
    cli_path = _find_copilot_cli()
    auth_configured = any(bool(os.environ.get(var)) for var in _AUTH_ENV_VARS)
    if cli_path is None:
        return AdapterProbeResult(
            adapter_type="cli",
            available=False,
            sdk_installed=False,
            cli_found=False,
            cli_path=None,
            auth_configured=auth_configured,
            details="Copilot CLI ('copilot' or ~/.local/share/gh/copilot) not found on host.",
            blocking_reason="Install GitHub Copilot CLI and authenticate with Copilot Business.",
        )

    if not auth_configured:
        return AdapterProbeResult(
            adapter_type="cli",
            available=False,
            sdk_installed=False,
            cli_found=True,
            cli_path=cli_path,
            auth_configured=False,
            details=f"Copilot CLI found at {cli_path}, but auth env token not set.",
            blocking_reason="Authenticate Copilot CLI (`copilot login` or COPILOT_GITHUB_TOKEN).",
        )

    return AdapterProbeResult(
        adapter_type="cli",
        available=True,
        sdk_installed=False,
        cli_found=True,
        cli_path=cli_path,
        auth_configured=True,
        details=f"Copilot CLI ready at {cli_path}.",
    )


class CopilotCliSubprocessAdapter(BaseWorkerAdapter):
    """WorkerAdapter running Copilot CLI (or injected command) in a new process group."""

    def __init__(
        self,
        policy: RolePolicy,
        *,
        command_builder: Callable[[WorkerAssignment, Path], list[str]] | None = None,
        sigterm_timeout: float = 0.8,
        sigkill_timeout: float = 0.5,
    ) -> None:
        super().__init__(policy)
        self._command_builder = command_builder
        self._sigterm_timeout = sigterm_timeout
        self._sigkill_timeout = sigkill_timeout

        self._runtime_dir: tempfile.TemporaryDirectory[str] | None = None
        self._sentinel_path: Path | None = None
        self._proc: asyncio.subprocess.Process | None = None
        self._pgid: int | None = None
        self._abort_requested = False
        self._scope_violation: ScopeViolationError | None = None
        self._quota_error: PausedQuota | None = None
        self.start_count = 0

    def _prepare_runtime_files(self, assignment: WorkerAssignment) -> tuple[Path, Path, Path]:
        self._runtime_dir = tempfile.TemporaryDirectory(prefix=f"thread-cli-{assignment.ticket_id}-")
        runtime_path = Path(self._runtime_dir.name)
        policy_path = runtime_path / "policy.json"
        sentinel_path = runtime_path / "violation.json"
        hooks_dir = runtime_path / "hooks"
        hooks_dir.mkdir(parents=True, exist_ok=True)
        hook_config_path = hooks_dir / "guard.json"

        policy_path.write_text(json.dumps(self._policy.to_dict()), encoding="utf-8")
        hook_cfg = {
            "version": 1,
            "hooks": {
                "preToolUse": [
                    {
                        "type": "command",
                        "bash": f"{sys.executable} -m thread_sdlc.workers.permissions",
                        "timeoutSec": 10,
                    }
                ]
            },
        }
        hook_config_path.write_text(json.dumps(hook_cfg), encoding="utf-8")
        self._sentinel_path = sentinel_path
        return runtime_path, policy_path, sentinel_path

    def _build_default_argv(self, assignment: WorkerAssignment, config_dir: Path) -> list[str]:
        cli_path = _find_copilot_cli()
        if cli_path is None:
            raise AdapterUnavailableError(
                "Copilot CLI binary not found; install `copilot` or configure COPILOT_CLI_PATH."
            )
        argv = [
            cli_path,
            "--prompt",
            assignment.instructions,
            "--config-dir",
            str(config_dir),
            "--output-format",
            "json",
            "--autopilot",
            "--max-autopilot-continues",
            str(assignment.max_turns),
            "--deny-tool",
            "shell(git merge)",
            "--deny-tool",
            "shell(git push)",
        ]
        if self._policy.readonly:
            for tool in ("write", "edit", "create", "delete", "apply_patch"):
                argv.extend(["--deny-tool", tool])
            if not self._policy.allowed_shell_prefixes:
                argv.extend(["--deny-tool", "shell"])
        return argv

    def _check_violation_sentinel(self) -> ScopeViolationError | None:
        if self._sentinel_path is not None and self._sentinel_path.is_file():
            try:
                data = json.loads(self._sentinel_path.read_text(encoding="utf-8"))
                return ScopeViolationError(
                    role=str(data.get("role", self._policy.role)),
                    operation=data.get("operation", "tool"),
                    target=str(data.get("target", "")),
                    reason=str(data.get("reason", "Blocked by preToolUse hook")),
                )
            except Exception:
                return ScopeViolationError(
                    self._policy.role, "tool", "<unknown>", "Blocked by preToolUse hook"
                )
        return None

    async def start(self, assignment: WorkerAssignment) -> None:
        self.start_count += 1
        self._assignment = assignment
        self._started_at_mono = time.monotonic()
        self._usage = UsageMetrics(model=assignment.model or "copilot-cli")
        self._abort_requested = False
        self._scope_violation = None
        self._quota_error = None

        if not assignment.worktree_path.exists():
            raise WorkerExecutionError(f"Worktree path does not exist: {assignment.worktree_path}")

        runtime_path, policy_path, sentinel_path = self._prepare_runtime_files(assignment)
        if self._command_builder is not None:
            argv = self._command_builder(assignment, runtime_path)
        else:
            argv = self._build_default_argv(assignment, runtime_path)

        if not argv:
            raise WorkerExecutionError("Empty command argv for CopilotCliSubprocessAdapter")

        env = os.environ.copy()
        env["THREAD_POLICY_PATH"] = str(policy_path)
        env["THREAD_VIOLATION_SENTINEL"] = str(sentinel_path)
        env["COPILOT_CLI_CONFIG_DIR"] = str(runtime_path)

        # Ensure src/ is importable if subprocess invokes `python -m thread_sdlc.workers.permissions`
        pkg_src = str(Path(__file__).resolve().parents[2])
        existing_pp = env.get("PYTHONPATH", "")
        if pkg_src not in existing_pp.split(os.pathsep):
            env["PYTHONPATH"] = f"{pkg_src}{os.pathsep}{existing_pp}" if existing_pp else pkg_src

        self._proc = await asyncio.create_subprocess_exec(
            *argv,
            cwd=str(assignment.worktree_path),
            env=env,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )
        try:
            self._pgid = os.getpgid(self._proc.pid)
        except OSError:
            self._pgid = self._proc.pid

    async def _read_pipe(
        self,
        stream: asyncio.StreamReader | None,
        stream_name: str,
        queue: asyncio.Queue[tuple[str, str] | None],
    ) -> None:
        if stream is None:
            await queue.put(None)
            return
        try:
            while True:
                raw = await stream.readline()
                if not raw:
                    break
                line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
                # Scrub IMMEDIATELY before buffering or emitting anywhere
                scrubbed = redactor.redact_text(line)
                await queue.put((stream_name, scrubbed))
        finally:
            await queue.put(None)

    async def stream_events(self) -> AsyncIterator[WorkerEvent]:
        if self._proc is None or self._assignment is None:
            raise WorkerExecutionError("CopilotCliSubprocessAdapter.stream_events called before start()")

        assignment = self._assignment
        yield self._redact_event(
            "session_start",
            f"Started Copilot CLI subprocess (pid={self._proc.pid}) for {assignment.ticket_id}",
            {"assignment_id": assignment.assignment_id, "pid": self._proc.pid},
        )

        queue: asyncio.Queue[tuple[str, str] | None] = asyncio.Queue()
        t_out = asyncio.create_task(self._read_pipe(self._proc.stdout, "stdout", queue))
        t_err = asyncio.create_task(self._read_pipe(self._proc.stderr, "stderr", queue))
        finished_pipes = 0

        try:
            while finished_pipes < 2:
                item = await queue.get()
                if item is None:
                    finished_pipes += 1
                    continue

                stream_name, scrubbed_line = item

                # Check sentinel written by `preToolUse` hook
                sentinel_err = self._check_violation_sentinel()
                if sentinel_err is not None:
                    self._scope_violation = sentinel_err
                    yield self._redact_event(
                        "scope_violation",
                        str(sentinel_err),
                        {
                            "role": sentinel_err.role,
                            "operation": sentinel_err.operation,
                            "target": sentinel_err.target,
                        },
                    )
                    await self.abort()
                    break

                # Inspect structured JSON lines if emitted
                parsed_json: dict[str, Any] | None = None
                if scrubbed_line.startswith("{") and scrubbed_line.endswith("}"):
                    try:
                        obj = json.loads(scrubbed_line)
                        if isinstance(obj, dict):
                            parsed_json = obj
                    except json.JSONDecodeError:
                        parsed_json = None

                if parsed_json is not None:
                    evt_type = str(parsed_json.get("type") or "")
                    if evt_type in ("tool_request", "pre_tool_use"):
                        t_name = str(parsed_json.get("toolName") or parsed_json.get("tool_name") or "")
                        t_args = parsed_json.get("toolArgs") or parsed_json.get("tool_args")
                        try:
                            self._policy.enforce_tool_call(t_name, t_args)
                        except ScopeViolationError as err:
                            self._scope_violation = err
                            yield self._redact_event(
                                "scope_violation",
                                str(err),
                                {"role": err.role, "operation": err.operation, "target": err.target},
                            )
                            await self.abort()
                            break

                    if evt_type == "usage" or "turns_used" in parsed_json or "credits_used" in parsed_json:
                        turns = int(parsed_json.get("turns_used", 1))
                        credits = float(parsed_json.get("credits_used", 1.0))
                        self._usage.turns_used += turns
                        self._usage.credits_used += credits
                        self._usage.input_tokens += int(parsed_json.get("input_tokens", 0))
                        self._usage.output_tokens += int(parsed_json.get("output_tokens", 0))
                        yield self._redact_event(
                            "usage",
                            "CLI usage recorded",
                            {
                                "turns_used": self._usage.turns_used,
                                "credits_used": self._usage.credits_used,
                            },
                        )
                        try:
                            self._check_caps(assignment, self._usage)
                        except PausedQuota as pq:
                            self._quota_error = pq
                            yield self._redact_event(
                                "paused_quota", str(pq), {"limit_type": pq.limit_type}
                            )
                            await self.abort()
                            break

                if is_quota_error(scrubbed_line):
                    pq = PausedQuota(
                        scrubbed_line,
                        limit_type="provider_quota",
                        credits_used=self._usage.credits_used,
                        turns_used=self._usage.turns_used,
                    )
                    self._quota_error = pq
                    yield self._redact_event(
                        "paused_quota", scrubbed_line, {"limit_type": "provider_quota"}
                    )
                    await self.abort()
                    break

                yield self._redact_event(stream_name, scrubbed_line)
        finally:
            for task in (t_out, t_err):
                if not task.done():
                    task.cancel()
            await asyncio.gather(t_out, t_err, return_exceptions=True)

        # Wait briefly for process exit and re-check sentinel
        if self._proc.returncode is None:
            try:
                await asyncio.wait_for(self._proc.wait(), timeout=1.0)
            except TimeoutError:
                await self.abort()

        if self._scope_violation is None:
            self._scope_violation = self._check_violation_sentinel()

        if self._scope_violation is not None:
            raise self._scope_violation
        if self._quota_error is not None:
            raise self._quota_error
        if self._abort_requested:
            yield self._redact_event("aborted", "Copilot CLI subprocess aborted")
            return

        rc = self._proc.returncode
        if rc not in (0, None):
            raise WorkerExecutionError(f"Copilot CLI subprocess exited with code {rc}")

        yield self._redact_event("session_idle", "Copilot CLI subprocess finished")

    async def abort(self) -> None:
        self._abort_requested = True
        self._usage.aborted = True
        proc = self._proc
        if proc is not None and proc.returncode is None:
            pgid = self._pgid or proc.pid
            try:
                os.killpg(pgid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            except OSError:
                try:
                    proc.terminate()
                except ProcessLookupError:
                    pass

            try:
                await asyncio.wait_for(proc.wait(), timeout=self._sigterm_timeout)
            except TimeoutError:
                try:
                    os.killpg(pgid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                except OSError:
                    try:
                        proc.kill()
                    except ProcessLookupError:
                        pass
                try:
                    await asyncio.wait_for(proc.wait(), timeout=self._sigkill_timeout)
                except TimeoutError:
                    pass

        if self._started_at_mono is not None:
            self._usage.duration_ms = (time.monotonic() - self._started_at_mono) * 1000.0

    async def disconnect(self) -> None:
        if self._proc is not None and self._proc.returncode is None:
            await self.abort()
        if self._runtime_dir is not None:
            self._runtime_dir.cleanup()
            self._runtime_dir = None
        if self._started_at_mono is not None:
            self._usage.duration_ms = (time.monotonic() - self._started_at_mono) * 1000.0
