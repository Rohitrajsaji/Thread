# Thread (`thread-sdlc`)

Installable, stack-agnostic, repository-native Agentic SDLC orchestrator for GitHub Copilot Business teams (VS Code Copilot Chat `@thread` + GitHub Copilot SDK/CLI) with a local `127.0.0.1` token-authenticated Approval & Review Web UI.

## Quickstart

```bash
uv venv --python 3.11 .venv
uv pip install --python .venv/bin/python -e ".[dev]"
.venv/bin/thread --help
.venv/bin/thread doctor --spike
```

### Optional Copilot SDK

To probe or run the live GitHub Copilot SDK adapter:

```bash
uv pip install --python .venv/bin/python -e ".[copilot]"
```

## Architecture

- **Canonical Repository Core (`.thread/`)**: `config.yaml`, `policy.yaml`, `scope.yaml`, `rules-map.yaml`, `constitution.md`
- **Durable Local State (`.thread-state/`)**: SQLite WAL database (`thread.db`), isolated worktrees (`.thread-state/worktrees/<ticket_id>`), and pre-storage secret-redacted logs (`.thread-state/redacted-logs/`)
- **Worker Adapters & Permissions**: `CopilotSdkAdapter`, `CopilotCliSubprocessAdapter`, and `MockWorkerAdapter` with fail-closed `RolePolicy` pre-write scope checks (`reviewer_readonly`, path/shell containment) and zero-retry `PausedQuota` handling
