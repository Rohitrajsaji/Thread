"""Git worktree management, trailer-based commit lookup, and human-only merge guard."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from pydantic import BaseModel, Field

_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9._-]+$")


class WorktreeError(Exception):
    """Raised when Git worktree setup or inspection fails."""


class WorktreeInfo(BaseModel):
    """Metadata for an isolated ticket worktree."""

    thread_id: str
    ticket_id: str
    branch: str
    path: Path
    base_sha: str
    head_sha: str


class WorktreeStatus(BaseModel):
    """Observed Git status for a ticket worktree."""

    exists: bool
    head_sha: str | None = None
    dirty_files: list[str] = Field(default_factory=list)
    commits_ahead: int = 0


class ReconcileResult(BaseModel):
    """Result of reconciling Git commit history against an assignment."""

    reconciled: bool
    status: str  # "reconciled_completed" | "completed" | "not_committed"
    assignment_id: str | None = None
    result_sha: str | None = None
    branch: str | None = None
    worktree_path: Path | None = None
    has_uncommitted_changes: bool = False


def _validate_id(value: str, label: str) -> str:
    if not value or value in (".", "..") or not _SAFE_ID_RE.match(value) or ".." in value:
        raise WorktreeError(f"Invalid {label}: {value!r}")
    return value


def _run_git(
    args: list[str],
    cwd: Path,
    *,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        ["git", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        check=False,
    )
    if check and proc.returncode != 0:
        raise WorktreeError(
            f"git {' '.join(args)} failed in {cwd}: {proc.stderr.strip() or proc.stdout.strip()}"
        )
    return proc


class WorktreeManager:
    """Manages `.thread-state/worktrees/<ticket_id>` and Git trailer reconciliation."""

    def __init__(self, repo_root: Path) -> None:
        self.repo_root = repo_root.resolve()
        self.worktrees_root = self.repo_root / ".thread-state" / "worktrees"

    def branch_name(self, thread_id: str, ticket_id: str) -> str:
        tid = _validate_id(thread_id, "thread_id")
        kid = _validate_id(ticket_id, "ticket_id")
        return f"thread/{tid}/{kid}"

    def worktree_path_for(self, ticket_id: str) -> Path:
        kid = _validate_id(ticket_id, "ticket_id")
        return (self.worktrees_root / kid).resolve()

    @staticmethod
    def commit_trailer(assignment_id: str) -> str:
        aid = _validate_id(assignment_id, "assignment_id")
        return f"Thread-Assignment-Id: {aid}"

    def ensure_worktree(
        self, thread_id: str, ticket_id: str, base_ref: str = "HEAD"
    ) -> WorktreeInfo:
        """Create or safely reuse a ticket worktree without clobbering uncommitted/committed state."""
        _validate_id(thread_id, "thread_id")
        _validate_id(ticket_id, "ticket_id")

        head_check = _run_git(["rev-parse", "--verify", "HEAD"], self.repo_root, check=False)
        if head_check.returncode != 0:
            raise WorktreeError(
                f"Repository at {self.repo_root} has no commits; create an initial commit first."
            )

        base_sha = _run_git(
            ["rev-parse", "--verify", f"{base_ref}^{{commit}}"], self.repo_root
        ).stdout.strip()
        branch = self.branch_name(thread_id, ticket_id)
        wt_path = self.worktree_path_for(ticket_id)
        self.worktrees_root.mkdir(parents=True, exist_ok=True)

        if wt_path.exists():
            inside = _run_git(
                ["rev-parse", "--is-inside-work-tree"], wt_path, check=False
            )
            cur_branch = _run_git(
                ["branch", "--show-current"], wt_path, check=False
            )
            if inside.returncode == 0 and cur_branch.stdout.strip() == branch:
                wt_head = _run_git(["rev-parse", "HEAD"], wt_path).stdout.strip()
                return WorktreeInfo(
                    thread_id=thread_id,
                    ticket_id=ticket_id,
                    branch=branch,
                    path=wt_path,
                    base_sha=base_sha,
                    head_sha=wt_head,
                )
            raise WorktreeError(
                f"Existing directory at {wt_path} does not match expected worktree branch {branch}"
            )

        branch_exists = (
            _run_git(
                ["show-ref", "--verify", f"refs/heads/{branch}"],
                self.repo_root,
                check=False,
            ).returncode
            == 0
        )

        if branch_exists:
            _run_git(["worktree", "prune"], self.repo_root, check=False)
            _run_git(["worktree", "add", str(wt_path), branch], self.repo_root)
        else:
            _run_git(
                ["worktree", "add", "-b", branch, str(wt_path), base_sha],
                self.repo_root,
            )

        wt_head = _run_git(["rev-parse", "HEAD"], wt_path).stdout.strip()
        return WorktreeInfo(
            thread_id=thread_id,
            ticket_id=ticket_id,
            branch=branch,
            path=wt_path,
            base_sha=base_sha,
            head_sha=wt_head,
        )

    def find_commit_by_assignment_id(
        self,
        assignment_id: str,
        branch_or_path: str | Path,
        base_sha: str | None = None,
    ) -> str | None:
        """Search Git commits for ``Thread-Assignment-Id: <assignment_id>`` trailer."""
        _validate_id(assignment_id, "assignment_id")

        if isinstance(branch_or_path, Path):
            if not branch_or_path.exists():
                return None
            cwd = branch_or_path
            rev_arg = f"{base_sha}..HEAD" if base_sha else "HEAD"
        else:
            cwd = self.repo_root
            ref_check = _run_git(
                ["rev-parse", "--verify", branch_or_path], self.repo_root, check=False
            )
            if ref_check.returncode != 0:
                return None
            rev_arg = f"{base_sha}..{branch_or_path}" if base_sha else branch_or_path

        log_args = [
            "log",
            rev_arg,
            "-n",
            "100",
            "--format=%H%x09%(trailers:key=Thread-Assignment-Id,valueonly=true,unfold=true,separator=%x2C)",
        ]
        proc = _run_git(log_args, cwd, check=False)
        if proc.returncode == 0:
            for line in proc.stdout.splitlines():
                if "\t" not in line:
                    continue
                sha, trailers_raw = line.split("\t", 1)
                values = [v.strip() for v in trailers_raw.split(",") if v.strip()]
                if assignment_id in values:
                    return sha.strip()

        # Fallback grep if trailer appeared above another paragraph (exact line match)
        grep_args = [
            "log",
            rev_arg,
            "-n",
            "100",
            "--extended-regexp",
            f"--grep=^Thread-Assignment-Id:[[:space:]]*{re.escape(assignment_id)}[[:space:]]*$",
            "--format=%H",
        ]
        grep_proc = _run_git(grep_args, cwd, check=False)
        if grep_proc.returncode == 0 and grep_proc.stdout.strip():
            return grep_proc.stdout.strip().splitlines()[0].strip()

        return None

    def inspect_worktree(
        self, worktree_path: Path, base_sha: str | None = None
    ) -> WorktreeStatus:
        """Inspect uncommitted files, HEAD SHA, and commit count ahead of ``base_sha``."""
        if not worktree_path.exists():
            return WorktreeStatus(exists=False)
        inside = _run_git(["rev-parse", "--is-inside-work-tree"], worktree_path, check=False)
        if inside.returncode != 0:
            return WorktreeStatus(exists=False)

        head_sha = _run_git(["rev-parse", "HEAD"], worktree_path).stdout.strip()
        status_out = _run_git(["status", "--porcelain"], worktree_path).stdout
        dirty = [line[3:].strip() for line in status_out.splitlines() if line.strip()]

        ahead = 0
        if base_sha:
            cnt_proc = _run_git(
                ["rev-list", "--count", f"{base_sha}..HEAD"], worktree_path, check=False
            )
            if cnt_proc.returncode == 0 and cnt_proc.stdout.strip().isdigit():
                ahead = int(cnt_proc.stdout.strip())

        return WorktreeStatus(
            exists=True,
            head_sha=head_sha,
            dirty_files=dirty,
            commits_ahead=ahead,
        )

    def reconcile_assignment(
        self,
        thread_id: str,
        ticket_id: str,
        assignment_id: str,
        base_sha: str | None = None,
    ) -> ReconcileResult:
        """Check worktree and branch Git history for ``Thread-Assignment-Id`` before dispatch."""
        branch = self.branch_name(thread_id, ticket_id)
        wt_path = self.worktree_path_for(ticket_id)

        sha = self.find_commit_by_assignment_id(assignment_id, wt_path, base_sha=base_sha)
        if sha is None:
            sha = self.find_commit_by_assignment_id(
                assignment_id, f"refs/heads/{branch}", base_sha=base_sha
            )

        status = self.inspect_worktree(wt_path, base_sha=base_sha)
        if sha is not None:
            return ReconcileResult(
                reconciled=True,
                status="reconciled_completed",
                assignment_id=assignment_id,
                result_sha=sha,
                branch=branch,
                worktree_path=wt_path,
                has_uncommitted_changes=bool(status.dirty_files),
            )

        return ReconcileResult(
            reconciled=False,
            status="not_committed",
            assignment_id=assignment_id,
            result_sha=None,
            branch=branch,
            worktree_path=wt_path,
            has_uncommitted_changes=bool(status.dirty_files),
        )

    def commit_worktree(
        self,
        worktree_path: Path,
        message: str,
        assignment_id: str,
        *,
        add_all: bool = True,
    ) -> str:
        """Stage and commit worktree changes with the required ``Thread-Assignment-Id`` trailer."""
        _validate_id(assignment_id, "assignment_id")
        if add_all:
            _run_git(["add", "--all"], worktree_path)
        full_msg = f"{message.rstrip()}\n\n{self.commit_trailer(assignment_id)}"
        _run_git(["commit", "-m", full_msg], worktree_path)
        return _run_git(["rev-parse", "HEAD"], worktree_path).stdout.strip()

    def merge_worktree_human_only(
        self,
        thread_id: str,
        ticket_id: str,
        target_branch: str = "main",
        *,
        human_authorized: bool = False,
    ) -> str:
        """Merge a completed ticket branch into ``target_branch`` ONLY when human-authorized."""
        if not human_authorized:
            raise PermissionError(
                "Workers are forbidden from merging into the base branch; human authorization is required."
            )
        branch = self.branch_name(thread_id, ticket_id)
        _run_git(["checkout", target_branch], self.repo_root)
        _run_git(["merge", "--no-ff", branch, "-m", f"Merge {branch} into {target_branch}"], self.repo_root)
        return _run_git(["rev-parse", "HEAD"], self.repo_root).stdout.strip()
