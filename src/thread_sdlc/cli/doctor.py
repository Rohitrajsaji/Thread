"""Org Copilot Spike Diagnostic (`thread doctor --spike`) comparing SDK and CLI adapters."""

from __future__ import annotations

import asyncio
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from rich.console import Console

from thread_sdlc.governance import redactor
from thread_sdlc.workers.adapter import MockWorkerAdapter, PausedQuota, WorkerAssignment
from thread_sdlc.workers.copilot_cli import CopilotCliSubprocessAdapter, probe_cli
from thread_sdlc.workers.copilot_sdk import CopilotSdkAdapter, probe_sdk
from thread_sdlc.workers.permissions import RolePolicy, ScopeViolationError

_AUTH_ENV_VARS = (
    "COPILOT_GITHUB_TOKEN",
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "GITHUB_COPILOT_TOKEN",
)


@dataclass
class DoctorCheckResult:
    """Single check outcome in `thread doctor --spike`."""

    name: str
    adapter: str  # "env" | "sdk" | "cli" | "mcp" | "quota"
    status: Literal["PASS", "FAIL", "BLOCKED", "SKIPPED"]
    duration_ms: float
    details: str
    remediation: str | None = None


@dataclass
class AdapterComparisonRow:
    """Side-by-side summary metrics for SDK vs CLI adapters."""

    adapter_name: str
    installed_or_binary: str
    live_auth: str
    pre_write_scope_block: str
    abort_latency: str
    quota_handling: str
    overall_status: str


@dataclass
class SpikeReport:
    """Structured diagnostic output produced by `run_spike_diagnostics`."""

    repo_root: Path
    live_copilot_available: bool
    checks: list[DoctorCheckResult] = field(default_factory=list)
    comparison: list[AdapterComparisonRow] = field(default_factory=list)
    unblocking_steps: list[str] = field(default_factory=list)

    @property
    def has_failures(self) -> bool:
        return any(c.status == "FAIL" for c in self.checks)


def _safe_run(cmd: list[str], cwd: Path, timeout: float = 5.0) -> tuple[int, str]:
    try:
        proc = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            stdin=subprocess.DEVNULL,
            timeout=timeout,
            check=False,
        )
        combined = (proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")
        return proc.returncode, redactor.redact_text(combined.strip())
    except FileNotFoundError:
        return 127, f"Command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, f"Command timed out after {timeout}s: {' '.join(cmd)}"


def _vscode_copilot_installed() -> bool:
    ext_dir = Path.home() / ".vscode" / "extensions"
    if not ext_dir.is_dir():
        return False
    for entry in ext_dir.iterdir():
        if "github.copilot" in entry.name.lower():
            return True
    return False


class _SpikeFakeSession:
    def __init__(self, on_permission_request: Any, hooks: dict[str, Any], worktree: Path) -> None:
        self._on_permission_request = on_permission_request
        self._hooks = hooks
        self._worktree = worktree
        self._handlers: list[Any] = []
        self._aborted = asyncio.Event()

    def on(self, handler: Any) -> None:
        self._handlers.append(handler)

    async def send(self, prompt: str) -> str:
        pre_hook = self._hooks.get("on_pre_tool_use")
        if prompt == "scope_probe":
            # Allowed path check via hook
            res_ok = await pre_hook(
                {"toolName": "write_file", "toolArgs": {"path": "app/ok.py"}}, {}
            )
            if res_ok.get("permissionDecision") != "allow":
                raise AssertionError(f"Expected allow for app/ok.py, got {res_ok}")

            # Disallowed path check BEFORE touching disk
            res_deny = await pre_hook(
                {"toolName": "write_file", "toolArgs": {"path": ".thread/policy.yaml"}}, {}
            )
            if res_deny.get("permissionDecision") == "allow":
                (self._worktree / ".thread").mkdir(parents=True, exist_ok=True)
                (self._worktree / ".thread" / "policy.yaml").write_text("tampered", encoding="utf-8")
            for h in self._handlers:
                h({"type": "session.idle", "data": {}})
            return "done"

        if prompt == "abort_probe":
            try:
                await asyncio.wait_for(self._aborted.wait(), timeout=10.0)
            except TimeoutError:
                pass
            return "aborted"

        return "ok"

    async def abort(self) -> None:
        self._aborted.set()
        for h in self._handlers:
            h({"type": "abort", "data": {}})

    async def disconnect(self) -> None:
        return None


class _SpikeFakeClient:
    def __init__(self, worktree: Path) -> None:
        self._worktree = worktree

    async def start(self) -> None:
        return None

    async def stop(self) -> None:
        return None

    async def create_session(self, **kwargs: Any) -> _SpikeFakeSession:
        return _SpikeFakeSession(
            kwargs["on_permission_request"],
            kwargs.get("hooks", {}),
            self._worktree,
        )


async def _probe_sdk_scope_and_abort(tmp_root: Path) -> tuple[DoctorCheckResult, DoctorCheckResult]:
    wt = tmp_root / "sdk_wt"
    wt.mkdir(parents=True, exist_ok=True)
    policy = RolePolicy(
        role="backend",
        worktree_root=wt,
        allowed_paths=["app/**"],
        denied_paths=[".thread/**"],
        deny_gate_files=[".thread/policy.yaml"],
    )

    # 1. Pre-write scope check
    t0 = time.perf_counter()
    adapter = CopilotSdkAdapter(policy, client_factory=lambda: _SpikeFakeClient(wt))
    asgn = WorkerAssignment(
        assignment_id="spike-sdk-scope",
        thread_id="spike",
        ticket_id="T-SDK-1",
        role="backend",
        instructions="scope_probe",
        worktree_path=wt,
        base_sha="HEAD",
    )
    blocked = False
    try:
        await adapter.start(asgn)
        async for _ in adapter.stream_events():
            pass
    except ScopeViolationError:
        blocked = True
    finally:
        await adapter.disconnect()

    protected_exists = (wt / ".thread" / "policy.yaml").exists()
    scope_ms = (time.perf_counter() - t0) * 1000.0
    if blocked and not protected_exists:
        scope_res = DoctorCheckResult(
            name="Pre-write scope block (SDK)",
            adapter="sdk",
            status="PASS",
            duration_ms=scope_ms,
            details="SDK preToolUse hook blocked .thread/policy.yaml before disk write (simulated session).",
        )
    else:
        scope_res = DoctorCheckResult(
            name="Pre-write scope block (SDK)",
            adapter="sdk",
            status="FAIL",
            duration_ms=scope_ms,
            details=f"blocked={blocked}, protected_exists={protected_exists}",
        )

    # 2. <2s abort check
    t1 = time.perf_counter()
    abort_adapter = CopilotSdkAdapter(policy, client_factory=lambda: _SpikeFakeClient(wt))
    abort_asgn = WorkerAssignment(
        assignment_id="spike-sdk-abort",
        thread_id="spike",
        ticket_id="T-SDK-2",
        role="backend",
        instructions="abort_probe",
        worktree_path=wt,
        base_sha="HEAD",
    )
    await abort_adapter.start(abort_asgn)
    await asyncio.sleep(0.05)
    t_abort_start = time.perf_counter()
    await abort_adapter.abort()
    abort_elapsed = time.perf_counter() - t_abort_start
    await abort_adapter.disconnect()
    total_ms = (time.perf_counter() - t1) * 1000.0

    abort_res = DoctorCheckResult(
        name="<2s abort latency (SDK)",
        adapter="sdk",
        status="PASS" if abort_elapsed < 2.0 else "FAIL",
        duration_ms=abort_elapsed * 1000.0,
        details=f"SDK session.abort() completed in {abort_elapsed * 1000.0:.1f}ms (total {total_ms:.1f}ms).",
    )
    return scope_res, abort_res


async def _probe_cli_scope_and_abort(tmp_root: Path) -> tuple[DoctorCheckResult, DoctorCheckResult]:
    wt = tmp_root / "cli_wt"
    wt.mkdir(parents=True, exist_ok=True)
    policy = RolePolicy(
        role="backend",
        worktree_root=wt,
        allowed_paths=["app/**"],
        denied_paths=[".thread/**"],
        deny_gate_files=[".thread/policy.yaml"],
    )

    # 1. Pre-write scope check via real subprocess invoking `python -m thread_sdlc.workers.permissions`
    hook_script = "\n".join(
        [
            "import json, subprocess, sys",
            "from pathlib import Path",
            "req = json.dumps({'toolName': 'write_file', 'toolArgs': {'path': '.thread/policy.yaml'}})",
            "p = subprocess.run([sys.executable, '-m', 'thread_sdlc.workers.permissions'], input=req, text=True, capture_output=True)",
            "dec = json.loads(p.stdout)",
            "print(json.dumps(dec))",
            "if dec.get('permissionDecision') == 'allow':",
            "    Path('.thread').mkdir(exist_ok=True)",
            "    Path('.thread/policy.yaml').write_text('tampered', encoding='utf-8')",
        ]
    )
    t0 = time.perf_counter()
    cli_adapter = CopilotCliSubprocessAdapter(
        policy,
        command_builder=lambda _a, _cfg: [sys.executable, "-c", hook_script],
    )
    asgn = WorkerAssignment(
        assignment_id="spike-cli-scope",
        thread_id="spike",
        ticket_id="T-CLI-1",
        role="backend",
        instructions="scope_probe",
        worktree_path=wt,
        base_sha="HEAD",
    )
    blocked = False
    try:
        await cli_adapter.start(asgn)
        async for _ in cli_adapter.stream_events():
            pass
    except ScopeViolationError:
        blocked = True
    finally:
        await cli_adapter.disconnect()

    protected_exists = (wt / ".thread" / "policy.yaml").exists()
    scope_ms = (time.perf_counter() - t0) * 1000.0
    if blocked and not protected_exists:
        scope_res = DoctorCheckResult(
            name="Pre-write scope block (CLI)",
            adapter="cli",
            status="PASS",
            duration_ms=scope_ms,
            details="CLI preToolUse hook subprocess blocked .thread/policy.yaml before disk write.",
        )
    else:
        scope_res = DoctorCheckResult(
            name="Pre-write scope block (CLI)",
            adapter="cli",
            status="FAIL",
            duration_ms=scope_ms,
            details=f"blocked={blocked}, protected_exists={protected_exists}",
        )

    # 2. <2s PGID SIGTERM->SIGKILL abort check on real subprocess
    abort_adapter = CopilotCliSubprocessAdapter(
        policy,
        command_builder=lambda _a, _cfg: [sys.executable, "-c", "import time; time.sleep(30)"],
    )
    abort_asgn = WorkerAssignment(
        assignment_id="spike-cli-abort",
        thread_id="spike",
        ticket_id="T-CLI-2",
        role="backend",
        instructions="abort_probe",
        worktree_path=wt,
        base_sha="HEAD",
    )
    await abort_adapter.start(abort_asgn)
    await asyncio.sleep(0.05)
    t_abort_start = time.perf_counter()
    await abort_adapter.abort()
    abort_elapsed = time.perf_counter() - t_abort_start
    await abort_adapter.disconnect()

    abort_res = DoctorCheckResult(
        name="<2s abort latency (CLI)",
        adapter="cli",
        status="PASS" if abort_elapsed < 2.0 else "FAIL",
        duration_ms=abort_elapsed * 1000.0,
        details=f"CLI process-group abort completed in {abort_elapsed * 1000.0:.1f}ms.",
    )
    return scope_res, abort_res


async def _probe_quota_simulation(tmp_root: Path) -> DoctorCheckResult:
    wt = tmp_root / "quota_wt"
    wt.mkdir(parents=True, exist_ok=True)
    policy = RolePolicy(role="backend", worktree_root=wt, allowed_paths=["app/**"])
    adapter = MockWorkerAdapter(policy, scenario="quota_exceeded", quota_mode="turns")
    asgn = WorkerAssignment(
        assignment_id="spike-quota",
        thread_id="spike",
        ticket_id="T-QUOTA-1",
        role="backend",
        instructions="quota_probe",
        worktree_path=wt,
        base_sha="HEAD",
        max_turns=2,
        max_credits=10.0,
    )
    t0 = time.perf_counter()
    paused_cleanly = False
    try:
        await adapter.start(asgn)
        async for _ in adapter.stream_events():
            pass
    except PausedQuota:
        paused_cleanly = True
    finally:
        await adapter.disconnect()

    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    if paused_cleanly and adapter.start_count == 1:
        return DoctorCheckResult(
            name="PausedQuota zero-retry simulation",
            adapter="quota",
            status="PASS",
            duration_ms=elapsed_ms,
            details="PausedQuota raised cleanly after 1 attempt with zero retry loop.",
        )
    return DoctorCheckResult(
        name="PausedQuota zero-retry simulation",
        adapter="quota",
        status="FAIL",
        duration_ms=elapsed_ms,
        details=f"paused_cleanly={paused_cleanly}, start_count={adapter.start_count}",
    )


def run_spike_diagnostics(repo_root: Path) -> SpikeReport:
    """Execute the full M0/M1 Org Copilot Spike diagnostic suite."""
    root = repo_root.resolve()
    checks: list[DoctorCheckResult] = []
    unblocking_steps: list[str] = []

    # 1. Environment & missing-CLI/auth diagnostics (strictly non-interactive)
    t0 = time.perf_counter()
    sdk_probe = probe_sdk()
    cli_probe = probe_cli()
    git_rc, git_ver = _safe_run(["git", "--version"], root)
    gh_rc, gh_auth = _safe_run(["gh", "auth", "status"], root)
    auth_env_present = [var for var in _AUTH_ENV_VARS if os.environ.get(var)]
    vscode_copilot = _vscode_copilot_installed()

    live_available = sdk_probe.available or cli_probe.available
    env_details = (
        f"python={sys.version.split()[0]}, git={git_ver if git_rc == 0 else 'missing'}, "
        f"gh_auth={'ok' if gh_rc == 0 else 'not-authenticated'}, "
        f"sdk_installed={sdk_probe.sdk_installed}, cli_found={cli_probe.cli_found}, "
        f"vscode_copilot={vscode_copilot}, auth_env_vars={auth_env_present or 'none'}"
    )
    checks.append(
        DoctorCheckResult(
            name="Environment & tool inventory",
            adapter="env",
            status="PASS" if git_rc == 0 else "FAIL",
            duration_ms=(time.perf_counter() - t0) * 1000.0,
            details=env_details,
        )
    )

    if not sdk_probe.available:
        checks.append(
            DoctorCheckResult(
                name="Live Copilot SDK auth/runtime",
                adapter="sdk",
                status="BLOCKED",
                duration_ms=0.1,
                details=sdk_probe.details,
                remediation=sdk_probe.blocking_reason,
            )
        )
        if sdk_probe.blocking_reason:
            unblocking_steps.append(sdk_probe.blocking_reason)
    else:
        checks.append(
            DoctorCheckResult(
                name="Live Copilot SDK auth/runtime",
                adapter="sdk",
                status="PASS",
                duration_ms=0.1,
                details=sdk_probe.details,
            )
        )

    if not cli_probe.available:
        checks.append(
            DoctorCheckResult(
                name="Live Copilot CLI binary & auth",
                adapter="cli",
                status="BLOCKED",
                duration_ms=0.1,
                details=cli_probe.details,
                remediation=cli_probe.blocking_reason,
            )
        )
        if cli_probe.blocking_reason:
            unblocking_steps.append(cli_probe.blocking_reason)
    else:
        checks.append(
            DoctorCheckResult(
                name="Live Copilot CLI binary & auth",
                adapter="cli",
                status="PASS",
                duration_ms=0.1,
                details=cli_probe.details,
            )
        )

    # 2. MCP Policy & Stdio probe
    t_mcp = time.perf_counter()
    mcp_spec = importlib.util.find_spec("mcp")
    mcp_json_exists = (root / ".vscode" / "mcp.json").is_file()
    checks.append(
        DoctorCheckResult(
            name="Local MCP package availability",
            adapter="mcp",
            status="PASS" if mcp_spec is not None else "FAIL",
            duration_ms=(time.perf_counter() - t_mcp) * 1000.0,
            details=f"mcp_installed={mcp_spec is not None}, .vscode/mcp.json={mcp_json_exists}",
        )
    )
    if not vscode_copilot:
        msg = "Install VS Code GitHub Copilot Chat extension and sign in with Copilot Business org policy allowing local stdio MCP."
        checks.append(
            DoctorCheckResult(
                name="Org VS Code MCP policy probe",
                adapter="mcp",
                status="BLOCKED",
                duration_ms=0.1,
                details="VS Code GitHub Copilot extension not detected in ~/.vscode/extensions.",
                remediation=msg,
            )
        )
        unblocking_steps.append(msg)

    # 3-5. Deterministic local adapter scope, abort, and quota checks
    with tempfile.TemporaryDirectory(prefix="thread-doctor-spike-") as tmpdir:
        tmp_root = Path(tmpdir)

        async def _run_async_probes() -> tuple[
            DoctorCheckResult,
            DoctorCheckResult,
            DoctorCheckResult,
            DoctorCheckResult,
            DoctorCheckResult,
        ]:
            sdk_scope, sdk_abort = await _probe_sdk_scope_and_abort(tmp_root)
            cli_scope, cli_abort = await _probe_cli_scope_and_abort(tmp_root)
            quota_res = await _probe_quota_simulation(tmp_root)
            return sdk_scope, sdk_abort, cli_scope, cli_abort, quota_res

        sdk_scope, sdk_abort, cli_scope, cli_abort, quota_res = asyncio.run(_run_async_probes())

    checks.extend([sdk_scope, cli_scope, sdk_abort, cli_abort, quota_res])

    comparison = [
        AdapterComparisonRow(
            adapter_name="CopilotSdkAdapter",
            installed_or_binary="Installed" if sdk_probe.sdk_installed else "Missing (optional extra)",
            live_auth="Ready" if sdk_probe.available else "BLOCKED (no CLI/token)",
            pre_write_scope_block=sdk_scope.status,
            abort_latency=f"{sdk_abort.duration_ms:.1f}ms ({sdk_abort.status})",
            quota_handling=quota_res.status,
            overall_status="PASS (simulated)" if sdk_scope.status == "PASS" and sdk_abort.status == "PASS" else "FAIL",
        ),
        AdapterComparisonRow(
            adapter_name="CopilotCliSubprocessAdapter",
            installed_or_binary=cli_probe.cli_path or "Missing (`copilot`)",
            live_auth="Ready" if cli_probe.available else "BLOCKED (no CLI/token)",
            pre_write_scope_block=cli_scope.status,
            abort_latency=f"{cli_abort.duration_ms:.1f}ms ({cli_abort.status})",
            quota_handling=quota_res.status,
            overall_status="PASS (simulated)" if cli_scope.status == "PASS" and cli_abort.status == "PASS" else "FAIL",
        ),
    ]

    return SpikeReport(
        repo_root=root,
        live_copilot_available=live_available,
        checks=checks,
        comparison=comparison,
        unblocking_steps=list(dict.fromkeys(unblocking_steps)),
    )


def render_spike_report(report: SpikeReport) -> str:
    """Render a `SpikeReport` as a clean Markdown diagnostic report."""
    lines: list[str] = [
        "# Thread Doctor — Org Copilot Spike Diagnostic Report",
        "",
        f"- **Repository:** `{report.repo_root}`",
        f"- **Python:** `{sys.version.split()[0]}`",
        f"- **Live Copilot Business Access:** `{'AVAILABLE' if report.live_copilot_available else 'BLOCKED (local harness checks simulated/verified)'}`",
        "",
        "## Adapter Comparison (`CopilotSdkAdapter` vs `CopilotCliSubprocessAdapter`)",
        "",
        "| Adapter | Package / Binary | Live Auth | Pre-Write Scope Block | `<2s` Abort Test | Quota Handling | Overall |",
        "|---|---|---|---|---|---|---|",
    ]
    for row in report.comparison:
        lines.append(
            f"| `{row.adapter_name}` | {row.installed_or_binary} | {row.live_auth} | "
            f"{row.pre_write_scope_block} | {row.abort_latency} | {row.quota_handling} | {row.overall_status} |"
        )

    lines.extend(
        [
            "",
            "## Detailed Checks",
            "",
            "| Check | Adapter | Status | Duration (ms) | Details |",
            "|---|---|---|---|---|",
        ]
    )
    for chk in report.checks:
        safe_details = redactor.redact_text(chk.details).replace("|", "\\|")
        lines.append(
            f"| {chk.name} | `{chk.adapter}` | **{chk.status}** | {chk.duration_ms:.1f} | {safe_details} |"
        )

    if report.unblocking_steps:
        lines.extend(["", "## Unblocking Steps for Live Copilot Business Verification", ""])
        for idx, step in enumerate(report.unblocking_steps, start=1):
            lines.append(f"{idx}. {step}")

    lines.append("")
    return "\n".join(lines)


def run_doctor_command(
    *,
    spike: bool = False,
    repo: Path = Path("."),
    output: Path | None = None,
    require_live: bool = False,
) -> int:
    """Execute `thread doctor` and return process exit code."""
    console = Console()
    if not spike:
        sdk_p = probe_sdk()
        cli_p = probe_cli()
        console.print(f"thread-sdlc doctor: sdk_installed={sdk_p.sdk_installed}, cli_found={cli_p.cli_found}")
        if require_live and not (sdk_p.available or cli_p.available):
            return 2
        return 0

    report = run_spike_diagnostics(repo)
    rendered = render_spike_report(report)
    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")

    import typer

    typer.echo(rendered)
    if report.has_failures:
        return 1
    if require_live and not report.live_copilot_available:
        return 2
    return 0
