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


@app.command("init")
def init_command(repo: Path = typer.Option(Path(".")), dry_run: bool = False):
    """Adopt Thread in a repository. Preview the patch with --dry-run."""
    from thread_sdlc.compiler.engine import apply
    typer.echo(apply(repo, initialize=True, preview=dry_run))


@app.command("compile")
def compile_command(repo: Path = typer.Option(Path(".")), check: bool = False):
    """Refresh the generated agent and repository integrations."""
    from thread_sdlc.compiler.engine import apply
    patch = apply(repo, preview=check)
    typer.echo(patch)
    if check and patch:
        raise typer.Exit(1)


@app.command("verify")
def verify_command(
    repo: Path = typer.Option(Path(".")),
    ci: bool = False,
    base_ref: str | None = typer.Option(None, help="Base Git ref or commit for verification."),
):
    """Verify the current checkout and emit the rule evidence."""
    from thread_sdlc.governance.engine import verify_repository
    report = verify_repository(repo.resolve(), ci=ci, base_sha=base_ref)
    typer.echo(report.model_dump_json(indent=2))
    if not report.passed:
        raise typer.Exit(1)


@app.command("mcp")
def mcp_command(repo: Path = typer.Option(Path("."))):
    """Serve the repository tools to VS Code over standard I/O."""
    from thread_sdlc.mcp_server.server import run
    run(repo.resolve())


@app.command("merge")
def merge_command(ticket_id: str, expected_head: str = typer.Option(...), expected_base: str = typer.Option(...), repo: Path = typer.Option(Path("."))):
    """Human authorization for merging the reviewed commit into its reviewed base."""
    from thread_sdlc.orchestrator.engine import Workflow
    typer.echo(Workflow(repo.resolve()).merge(ticket_id, expected_head, expected_base))


@app.command("ui")
def ui_command(repo: Path = typer.Option(Path(".")), port: int | None = typer.Option(None, min=0,max=65535)):
    """Launch the local browser review service."""
    import secrets
    import socket
    import uvicorn
    from thread_sdlc.config.loader import load_thread_config
    from thread_sdlc.ui.api import create_app
    requested = load_thread_config(repo).ui_port if port is None else port
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", requested))
        actual = listener.getsockname()[1]
        token = secrets.token_urlsafe(32)
        server = uvicorn.Server(uvicorn.Config(create_app(repo.resolve(), token, actual), access_log=False))
        typer.echo(f"Open http://127.0.0.1:{actual}/?token={token}")
        server.run(sockets=[listener])
