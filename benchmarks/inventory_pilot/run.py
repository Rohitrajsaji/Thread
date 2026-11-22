"""Run the paired, mock INV-101 pilot against independent Git checkouts."""
from __future__ import annotations

import argparse
import asyncio
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import secrets
from statistics import median
import subprocess
import sys
import tarfile
from tempfile import TemporaryDirectory
from time import monotonic
from xml.etree import ElementTree

from fastapi.testclient import TestClient
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
import yaml

from thread_sdlc.orchestrator.engine import Workflow
from thread_sdlc.ui.api import create_app
from thread_sdlc.workers.adapter import MockWorkerAdapter


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = "examples/inventory-app"
DEFAULT_REVISION = "ecfb9ab8c9c240b3aca93c5bb3ed62369da65fbe"
SOURCE = "app/inventory.py"
CONFIG = ".thread/config.yaml"
ARTIFACTS = ["docs/stories/INV-101.md", "contracts/openapi.yaml"]
REQUEST = "Implement INV-101 Inventory Reservations using the story and OpenAPI contract."
PORT = 4242
ORIGIN = f"http://127.0.0.1:{PORT}"
ORIGIN_HEADERS = {"Origin": ORIGIN}
TICKET = "inv-101"
MOCK_CREDITS_PER_TURN = 1
CHECKS = {
    "BR-INV-01": "test_last_unit_race",
    "BR-INV-02": "test_reservation_expiry",
    "OpenAPI conformance": "test_openapi_conformance",
}
SESSION_TIMEOUT = 20

DIRECT_CHILD = """
from hashlib import sha256
import json
import pathlib
import sys
import time

started = time.monotonic()
source, request, *artifacts = sys.argv[1:]
context = [request, *(pathlib.Path(path).read_text(encoding="utf-8") for path in artifacts)]
digest = sha256(json.dumps(context, ensure_ascii=False).encode()).hexdigest()
print(json.dumps([digest, time.monotonic() - started]), flush=True)
candidate = sys.stdin.buffer.read()
if candidate:
    pathlib.Path(source).write_bytes(candidate)
    print("candidate written", flush=True)
"""


def require(condition: bool, description: str) -> None:
    if not condition:
        raise RuntimeError(description)


def git(repo: Path, *args: str, env: dict[str, str] | None = None) -> str:
    return subprocess.run(
        ["git", *args], cwd=repo, env=env, check=True, capture_output=True, text=True, timeout=30,
    ).stdout.strip()


def identify(repo: Path) -> None:
    git(repo, "config", "user.name", "Inventory Pilot")
    git(repo, "config", "user.email", "inventory-pilot@example.test")


def build_baseline(scratch: Path, revision: str) -> tuple[Path, str, bytes]:
    baseline = scratch / "baseline"
    baseline.mkdir()
    archive = scratch / "fixture.tar"
    git(ROOT, "archive", "--format=tar", "-o", str(archive), f"{revision}:{FIXTURE}")
    with tarfile.open(archive) as contents:
        contents.extractall(baseline, filter="data")

    source = baseline / SOURCE
    candidate = source.read_bytes()
    start = candidate.index(b"\n", candidate.index(b"    def reserve("))
    end = candidate.index(b"\n    @app.delete(", start)
    placeholder = b'\n        raise HTTPException(501, "Reservations are not implemented")\n'
    source.write_bytes(candidate[:start] + placeholder + candidate[end:])
    (baseline / ".gitignore").write_text(".thread-state/\n", encoding="utf-8")

    git(baseline, "init", "--quiet", "--initial-branch=main")
    identify(baseline)
    git(baseline, "add", "--all")
    date = "2000-01-01T00:00:00+00:00"
    git(
        baseline, "commit", "--quiet", "-m", "Prepare incomplete INV-101 pilot fixture",
        env=dict(os.environ, GIT_AUTHOR_DATE=date, GIT_COMMITTER_DATE=date),
    )
    return baseline, git(baseline, "rev-parse", "HEAD"), candidate


def clone_baseline(baseline: Path, arm: str, base_sha: str) -> Path:
    repo = baseline.parent / arm
    git(baseline.parent, "clone", "--quiet", "--", str(baseline), str(repo))
    identify(repo)
    require(git(repo, "rev-parse", "HEAD") == base_sha, f"{arm} starts at a different commit")
    return repo


def acceptance(repo: Path) -> tuple[int, dict[str, bool]]:
    report = repo.parent / f"{repo.name}-pytest.xml"
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", f"--junitxml={report}"],
        cwd=repo, env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTEST_DISABLE_PLUGIN_AUTOLOAD="1"),
        text=True, capture_output=True, timeout=60,
    )
    require(report.exists(), f"Fixture checks produced no result in {repo.name}\n{result.stdout}\n{result.stderr}")
    cases = {
        case.get("name"): all(case.find(tag) is None for tag in ("failure", "error", "skipped"))
        for case in ElementTree.parse(report).iter("testcase")
    }
    require(all(name in cases for name in CHECKS.values()), f"Required fixture checks missing in {repo.name}")
    checks = {label: cases[name] for label, name in CHECKS.items()}
    checks["Fixture regression suite"] = result.returncode == 0 and all(cases.values())
    if result.returncode and repo.name != "baseline":
        print(result.stdout, file=sys.stderr)
    return result.returncode, checks


@dataclass
class Evidence:
    checks: dict[str, bool] = field(default_factory=dict)
    interventions: list[str] = field(default_factory=list)
    chat_actions: list[str] = field(default_factory=list)
    worker_turns: int = 0
    worker_credits: float = 0.0
    recovery_seconds: float = 0.0
    rework_seconds: float = 0.0
    wall_seconds: float = 0.0

    @property
    def turns(self) -> int:
        return len(self.chat_actions) + self.worker_turns

    @property
    def credits(self) -> float:
        return len(self.chat_actions) * MOCK_CREDITS_PER_TURN + self.worker_credits


@asynccontextmanager
async def direct_session(repo: Path):
    process = await asyncio.create_subprocess_exec(
        sys.executable, "-I", "-c", DIRECT_CHILD, SOURCE, REQUEST, *ARTIFACTS,
        cwd=repo, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
    )
    try:
        handshake = await asyncio.wait_for(process.stdout.readline(), SESSION_TIMEOUT)
        digest, context_seconds = json.loads(handshake)
        yield process, digest, context_seconds
    finally:
        if process.returncode is None:
            process.terminate()
            await asyncio.wait_for(process.wait(), SESSION_TIMEOUT)


async def direct_arm(repo: Path, candidate: bytes) -> Evidence:
    evidence = Evidence()
    started = monotonic()
    async with direct_session(repo) as (first, digest, _):
        evidence.chat_actions.append("Read request and fixture artifacts")
    require(first.returncode is not None and first.returncode != 0, "Direct mock session did not terminate")
    restart = monotonic()
    evidence.interventions.append("Resubmit the request and artifacts in a fresh session")
    async with direct_session(repo) as (second, recovered_digest, rebuilt):
        require(recovered_digest == digest, "Direct mock resumed with different context")
        evidence.recovery_seconds = monotonic() - restart
        evidence.rework_seconds = rebuilt
        evidence.chat_actions.append("Rebuild request context")
        stdout, _ = await asyncio.wait_for(second.communicate(candidate), SESSION_TIMEOUT)
        require(second.returncode == 0 and stdout.strip() == b"candidate written", "Direct candidate write failed")
        evidence.chat_actions.append("Apply the scripted candidate")
    evidence.checks["Session-close recovery"] = True
    git(repo, "add", "--", SOURCE)
    evidence.interventions.append("Accept the candidate and commit directly")
    git(repo, "commit", "--quiet", "-m", "Implement INV-101")
    _, acceptance_checks = acceptance(repo)
    evidence.checks.update(acceptance_checks)
    evidence.wall_seconds = monotonic() - started
    return evidence


@asynccontextmanager
async def thread_session(repo: Path):
    parameters = StdioServerParameters(
        command=sys.executable,
        args=["-c", "from thread_sdlc.cli.main import app; app()", "mcp", "--repo", str(repo)],
        cwd=repo,
        env={"PYTHONPATH": str(ROOT / "src"), "PYTHONDONTWRITEBYTECODE": "1"},
    )
    async with stdio_client(parameters) as (reader, writer):
        async with ClientSession(reader, writer) as session:
            await asyncio.wait_for(session.initialize(), SESSION_TIMEOUT)
            yield session


async def call_tool(session: ClientSession, name: str, **arguments):
    result = await asyncio.wait_for(session.call_tool(name, arguments), SESSION_TIMEOUT)
    payload = result.model_dump(by_alias=True)
    require(not payload.get("isError"), f"MCP tool {name} failed: {payload['content']}")
    if payload.get("structuredContent") is not None:
        return payload["structuredContent"]
    return json.loads(payload["content"][0]["text"])


def approve(ui: TestClient, checkpoint: dict) -> None:
    response = ui.post(
        f"/api/checkpoints/{checkpoint['id']}/decide",
        json={
            "decision": "approved", "content_sha256": checkpoint["content_sha256"],
            "git_head_sha": checkpoint["git_head_sha"],
        },
        headers=ORIGIN_HEADERS,
    )
    require(response.status_code == 200, f"Checkpoint approval failed: {response.text}")


class PilotWorkflow(Workflow):
    """Supply fixture output only, retaining the actual worker and worktree path."""

    def __init__(self, repo: Path, candidate: bytes):
        super().__init__(repo)
        self.candidate = candidate

    def _adapter(self, policy):
        return MockWorkerAdapter(
            policy, allowed_file_relpath=SOURCE, allowed_content=self.candidate.decode(),
            credits_per_turn=MOCK_CREDITS_PER_TURN,
        )


async def thread_arm(repo: Path, candidate: bytes, base_sha: str) -> Evidence:
    evidence = Evidence()
    started = monotonic()
    token = secrets.token_urlsafe(24)
    with TestClient(create_app(repo, token, PORT), base_url=ORIGIN) as ui:
        login = ui.get("/", params={"token": token}, follow_redirects=False)
        require(login.status_code == 303, "Could not authenticate the Thread reviewer")
        async with thread_session(repo) as session:
            task = await call_tool(session, "thread_start_or_resume", request=REQUEST, artifacts=ARTIFACTS)
            require(task["thread"]["track"] == 3, "The INV-101 request did not use Track 3")
            thread_id = task["thread"]["id"]
            story = (repo / ARTIFACTS[0]).read_text(encoding="utf-8")
            spec = await call_tool(
                session, "thread_save_checkpoint", thread_id=thread_id, stage="spec", content_md=story,
            )
            require(spec["status"] == "pending", "The spec is not pending at interruption")
            evidence.chat_actions.append("Submit request and draft the spec")

        # Both stdio streams are closed before approval. A fresh subprocess
        # must read the original checkpoint and its approval from storage.
        approve(ui, spec)
        evidence.interventions.append("Approve the spec")
        restart = monotonic()
        async with thread_session(repo) as restarted:
            resumed = await call_tool(restarted, "thread_start_or_resume", thread_id=thread_id)
            original = await call_tool(
                restarted, "thread_check_review", thread_id=thread_id, checkpoint_id=spec["id"],
            )
            checkpoint = original["checkpoint"]
            require(
                resumed["thread"]["status"] == "PlanDraft" and checkpoint["status"] == "approved"
                and checkpoint["content_sha256"] == spec["content_sha256"]
                and checkpoint["git_head_sha"] == base_sha,
                "Restart did not recover the same revision-bound spec",
            )
            evidence.recovery_seconds = monotonic() - restart
            evidence.checks["Session-close recovery"] = True
            await call_tool(
                restarted, "thread_plan_tickets", thread_id=thread_id,
                tickets=[{"id": TICKET, "title": REQUEST, "role": "backend", "paths": [SOURCE]}],
            )
            plan = await call_tool(
                restarted, "thread_save_checkpoint", thread_id=thread_id, stage="plan",
                content_md="Serialize last-unit reservations and release expired allocations.",
            )
            evidence.chat_actions.append("Resume the task and draft the plan")
        approve(ui, plan)
        evidence.interventions.append("Approve the plan")

        workflow = PilotWorkflow(repo, candidate)
        result = await workflow.dispatch_worker(thread_id, TICKET, REQUEST)
        require(result["status"] == "completed" and result["worker_invoked"], "Mock worker did not complete")
        head = result["result_sha"]
        verified = workflow.verify(thread_id, TICKET)
        observed = {proof["rule_id"] for proof in verified["rule_evidence"] if
                    proof["commit_sha"] == head and proof["provenance"] == "observed"
                    and proof["outcome"] == "passed"}
        require(
            verified["passed"] and verified["commit_sha"] == head and observed == {"BR-INV-01", "BR-INV-02"},
            f"Thread verification failed: {verified}",
        )
        merge = ui.post(
            f"/api/tickets/{TICKET}/merge", json={"expected_head": head, "expected_base": base_sha},
            headers=ORIGIN_HEADERS,
        )
        require(merge.status_code == 200 and git(repo, "rev-parse", "HEAD") == head, "Reviewed merge failed")
        evidence.interventions.append("Approve and merge the verified revision")
        completed = workflow.complete(thread_id)["thread"]
        evidence.worker_credits = completed["credits_used"]
        evidence.worker_turns = completed["turns_used"]

    _, acceptance_checks = acceptance(repo)
    evidence.checks.update(acceptance_checks)
    evidence.wall_seconds = monotonic() - started
    return evidence


def checked_tree(repo: Path, base_sha: str, candidate: bytes) -> str:
    require((repo / SOURCE).read_bytes() == candidate, "Benchmark arms produced different candidates")
    require(git(repo, "status", "--porcelain") == "", f"Uncommitted changes remain in {repo.name}")
    require(git(repo, "diff", "--name-only", base_sha, "HEAD") == SOURCE, "Candidate changed a fixture check or input")
    return git(repo, "rev-parse", "HEAD^{tree}")


def run_pairs(revision: str, pair_count: int) -> tuple[str, str, dict[str, bool], list[tuple[Evidence, Evidence]]]:
    with TemporaryDirectory(prefix="thread-inventory-pilot-", dir="/tmp") as folder:
        scratch = Path(folder).resolve()
        baseline, base_sha, candidate = build_baseline(scratch, revision)
        baseline_exit, baseline_checks = acceptance(baseline)
        require(
            baseline_exit == 1 and not any(baseline_checks[key] for key in CHECKS),
            "Expected the incomplete baseline to fail both business rules and runtime contract checks",
        )
        pairs = []
        candidate_tree = None
        for index in range(1, pair_count + 1):
            direct = clone_baseline(baseline, f"direct-{index}", base_sha)
            thread = clone_baseline(baseline, f"thread-{index}", base_sha)
            # Alternate order to reduce the effect of local process and filesystem caches.
            if index % 2:
                direct_result = asyncio.run(direct_arm(direct, candidate))
                thread_result = asyncio.run(thread_arm(thread, candidate, base_sha))
            else:
                thread_result = asyncio.run(thread_arm(thread, candidate, base_sha))
                direct_result = asyncio.run(direct_arm(direct, candidate))
            direct_tree = checked_tree(direct, base_sha, candidate)
            thread_tree = checked_tree(thread, base_sha, candidate)
            require(direct_tree == thread_tree, f"Pair {index} finished with different Git trees")
            require(candidate_tree is None or direct_tree == candidate_tree, "Candidate tree changed between pairs")
            candidate_tree = direct_tree
            pairs.append((direct_result, thread_result))
        return base_sha, candidate_tree, baseline_checks, pairs


def status(passed: bool) -> str:
    return "PASS" if passed else "FAIL"


def render_report(
    revision: str,
    base_sha: str,
    candidate_tree: str,
    baseline_checks: dict[str, bool],
    pairs: list[tuple[Evidence, Evidence]],
) -> str:
    direct, thread = zip(*pairs)
    stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    checks = [*CHECKS, "Fixture regression suite", "Session-close recovery"]
    passed = all(result.checks[key] for pair in pairs for result in pair for key in checks)
    rows = [
        "# INV-101 pilot benchmark",
        "",
        f"Generated {stamp} with Python {sys.version.split()[0]}.",
        f"Fixture source revision `{revision}`. Both arms began at `{base_sha}`.",
        f"Both arms produced Git tree `{candidate_tree}`.",
        "",
        f"**Mock pilot** {status(passed)} across {len(pairs)} paired runs.",
        "**Live Copilot benchmark** BLOCKED.",
        "**Live organization walkthrough** BLOCKED.",
        "**Milestone 3** Pending live evidence.",
        "",
        "| Measurement | Direct Copilot mock | Thread mock |",
        "| --- | ---: | ---: |",
    ]
    for check in checks:
        rows.append(
            f"| {check} | {status(all(run.checks[check] for run in direct))} | "
            f"{status(all(run.checks[check] for run in thread))} |"
        )
    for label, attribute, precision in (
        ("Wall-clock median (seconds)", "wall_seconds", 3),
        ("Scripted credits, chat and worker", "credits", 0),
        ("Scripted turns, chat and worker", "turns", 0),
        ("Restart to recovered context median (seconds)", "recovery_seconds", 4),
        ("Context rework median (seconds)", "rework_seconds", 6),
    ):
        direct_value = median(getattr(run, attribute) for run in direct)
        thread_value = median(getattr(run, attribute) for run in thread)
        rows.append(f"| {label} | {direct_value:.{precision}f} | {thread_value:.{precision}f} |")
    rows.extend([
        f"| Scripted human interventions | {median(len(run.interventions) for run in direct):g} | "
        f"{median(len(run.interventions) for run in thread):g} |",
        "",
        "## Per-pair timing",
        "",
        "| Pair | Direct wall (s) | Thread wall (s) | Direct restart (s) | Thread restart (s) | Direct rework (s) | Thread rework (s) |",
        "| ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ])
    for index, (first, second) in enumerate(pairs, 1):
        rows.append(
            f"| {index} | {first.wall_seconds:.3f} | {second.wall_seconds:.3f} | "
            f"{first.recovery_seconds:.4f} | {second.recovery_seconds:.4f} | "
            f"{first.rework_seconds:.6f} | {second.rework_seconds:.6f} |"
        )
    rows.extend([
        "",
        f"The incomplete baseline returned {', '.join(f'{key} {status(baseline_checks[key])}' for key in CHECKS)} as expected. Both final trees ran the unchanged fixture suite.",
        "Direct interventions were resubmitting the request and accepting the candidate into Git.",
        "Thread interventions were the authenticated spec approval, plan approval, and merge.",
        f"Direct executed {len(direct[0].chat_actions)} scripted chat actions. Thread executed "
        f"{len(thread[0].chat_actions)} scripted chat actions and recorded {thread[0].worker_turns} "
        "turn in the mock worker's durable usage totals. Each scripted turn consumes one mock credit.",
        "",
        "## Live dependencies and expansion",
        "",
        "The release closeout diagnostic `thread doctor --spike --require-live` returned exit 2. "
        "The organization Copilot CLI, Copilot Business authentication, and the VS Code Copilot Chat "
        "extension were unavailable.",
        "",
        "Install the organization-approved Copilot CLI and put it on PATH or set `COPILOT_CLI_PATH`. "
        "Authenticate with the Copilot Business account, supply the approved SDK credential, and confirm "
        "the optional SDK is installed. Install and sign into GitHub Copilot Chat in VS Code with local "
        "stdio MCP allowed by organization policy. Re-run `thread doctor --spike --require-live` and "
        "follow the matched live protocol in the README once it passes.",
        "",
        "The local timings include actual process lifecycle, Git, and fixture work. Thread also runs "
        "revision-bound approvals and clean-checkout verification before the final acceptance run. "
        "The simulated turns and approvals do not estimate provider billing, live model latency, "
        "or human review time. The observed orchestration overhead and persisted spec recovery are "
        "useful harness checks. They leave the live cost-benefit comparison and Milestone 3 decisions pending.",
        "",
    ])
    return "\n".join(rows)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture-revision", default=DEFAULT_REVISION, help="Git revision supplying the fixture")
    parser.add_argument("--pairs", type=int, default=3, help="Number of matched mock pairs")
    outputs = parser.add_mutually_exclusive_group()
    outputs.add_argument(
        "--report", type=Path, default=Path(__file__).resolve().with_name("REPORT.md"),
        help="Markdown report path (defaults to REPORT.md beside the runner)",
    )
    outputs.add_argument("--prepare-live", type=Path, metavar="DIRECTORY",
                         help="Prepare two identical external Git checkouts for the manual live protocol")
    args = parser.parse_args()
    if args.pairs < 1:
        parser.error("--pairs must be positive")
    revision = git(ROOT, "rev-parse", "--verify", "--end-of-options", f"{args.fixture_revision}^{{commit}}")
    if args.prepare_live:
        directory = args.prepare_live.resolve()
        if directory.is_relative_to(ROOT):
            parser.error("--prepare-live requires an external directory")
        directory.mkdir()
        baseline, base_sha, _ = build_baseline(directory, revision)
        for arm in ("direct", "thread"):
            clone_baseline(baseline, arm, base_sha)
        print(f"Prepared Direct and Thread checkouts at baseline {base_sha}.")
        return 0

    base_sha, candidate, baseline_checks, pairs = run_pairs(revision, args.pairs)
    report = render_report(revision, base_sha, candidate, baseline_checks, pairs)
    args.report.write_text(report, encoding="utf-8")
    print(report, end="")
    return 0 if all(all(result.checks.values()) for pair in pairs for result in pair) else 1


if __name__ == "__main__":
    raise SystemExit(main())
