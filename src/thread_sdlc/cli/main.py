"""Typer CLI entrypoint for `thread` (`thread-sdlc`)."""

from __future__ import annotations

from pathlib import Path

import typer

from thread_sdlc.cli.doctor import run_doctor_command

app = typer.Typer(
    name="thread",
    help="Thread (thread-sdlc) — Repository-native Agentic SDLC orchestrator.",
    no_args_is_help=True,
)


@app.callback()
def main_callback() -> None:
    """Thread (thread-sdlc) CLI."""


@app.command("doctor")
def doctor_command(
    spike: bool = typer.Option(
        False,
        "--spike",
        help="Run the M0/M1 Org Copilot Spike diagnostic harness (SDK vs CLI, scope, <2s abort, PausedQuota).",
    ),
    repo: Path = typer.Option(
        Path("."),
        "--repo",
        help="Target repository path.",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        help="Optional path to write the Markdown diagnostic report.",
    ),
    require_live: bool = typer.Option(
        False,
        "--require-live",
        help="Exit non-zero when live Copilot Business CLI/SDK auth is unavailable.",
    ),
) -> None:
    """Diagnose local environment, Copilot SDK/CLI adapters, permissions, and quota handling."""
    exit_code = run_doctor_command(
        spike=spike,
        repo=repo,
        output=output,
        require_live=require_live,
    )
    if exit_code != 0:
        raise typer.Exit(code=exit_code)
