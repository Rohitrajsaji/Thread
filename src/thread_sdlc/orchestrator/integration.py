"""Build reproducible combined proposals while leaving the target branch untouched."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from thread_sdlc.workers.worktree import WorktreeError


def combine(path: Path, heads: list[tuple[str, str]]) -> None:
    """Merge ticket heads in order into a disposable checkout."""
    timestamp = subprocess.check_output(
        ["git", "show", "-s", "--format=%ct", "HEAD"], cwd=path, text=True,
    ).strip()
    date = f"@{timestamp} +0000"
    env = dict(os.environ, GIT_AUTHOR_DATE=date, GIT_COMMITTER_DATE=date)
    for ticket_id, head in heads:
        result = subprocess.run(
            ["git", "-c", "core.hooksPath=/dev/null", "-c", "user.name=Thread Integration",
             "-c", "user.email=integration@thread.local", "merge", "--ff", "--no-gpg-sign", "--no-edit",
             "-m", f"Integrate ticket {ticket_id}", head],
            cwd=path, env=env, text=True, capture_output=True, check=False,
        )
        if result.returncode:
            paths = subprocess.check_output(
                ["git", "diff", "--name-only", "--diff-filter=U"], cwd=path, text=True,
            ).splitlines()
            detail = f" ({', '.join(paths)})" if paths else ""
            raise WorktreeError(f"Could not integrate ticket {ticket_id}{detail}")
