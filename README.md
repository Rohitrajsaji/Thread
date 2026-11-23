# Thread (`thread-sdlc`)

Installable, stack-agnostic, repository-native Agentic SDLC orchestrator for GitHub Copilot Business teams (VS Code Copilot Chat `@thread` + GitHub Copilot SDK/CLI) with a local `127.0.0.1` token-authenticated Approval & Review Web UI.

## Install the CLI

Thread requires Python 3.11 or later. Install directly from GitHub with pip or uv.

```bash
python -m pip install "git+https://github.com/Rohitrajsaji/Thread.git"
# Or install the CLI in an isolated uv tool environment.
uv tool install "git+https://github.com/Rohitrajsaji/Thread.git"
```

If you have a release wheel URL, install that artifact directly.

```bash
python -m pip install "<wheel-url>"
```

After building the wheel locally, install it from `dist/`.

```bash
python -m pip install ./dist/thread_sdlc-0.1.0-py3-none-any.whl
thread --help
thread doctor
```

## Develop locally

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

## Milestone 3 opt-ins

The four expansion modules default to off. In an adopted repository, enable the features you want in `.thread/config.yaml`.

```yaml
features:
  m3a: true
  m3b: true
  m3c: true
  m3d: true
```

- **3A** runs ready DAG tickets in parallel and verifies a single combined proposal before human approval. Set `caps.max_workers_per_thread` above one in `.thread/policy.yaml` to permit concurrency.
- **3B** runs fresh, read-only Goldfish reviews using the repository constitution and the selected spec or diff. Use `caps.max_goldfish_reviews` to configure the review limit.
- **3C** adds a local structural index, lexical search, offloaded tool output, and a knowledge graph whose edges record observed or inferred provenance.
- **3D** adds authenticated Mission Control views for the graph, memory promotion, and configuration. The graph view uses the 3C index.

Run `thread compile` after changing flags and restart the MCP session to refresh the available tools. An unmodified configuration still exposes the eight Milestone 1 tools. Live Copilot Business org verification remains pending organization access.

The context index searches locally with SQLite FTS5. For optional semantic search, install FastEmbed separately and set `THREAD_CONTEXT_MODEL_DIR` to a directory containing provisioned model files. Set `THREAD_CONTEXT_MODEL_NAME` if the files use a model other than `BAAI/bge-small-en-v1.5`. Missing models or runtime packages fall back to lexical search. Use `thread_offload_context` with `kind: diff` or `kind: test` for a compact preview and `thread_fetch_context` to page through the stored result.
