# INV-101 pilot benchmark

Generated 2026-11-22T15:33:39+00:00 with Python 3.11.13.
Fixture source revision `ecfb9ab8c9c240b3aca93c5bb3ed62369da65fbe`. Both arms began at `31515c370aca1105ce5a5a952b5574e4aaa0029b`.
Both arms produced Git tree `86eff6f38c9f5070394f94dff487c1f55ce04947`.

**Mock pilot** PASS across 3 paired runs.
**Live Copilot benchmark** BLOCKED.
**Live organization walkthrough** BLOCKED.
**Milestone 3** Pending live evidence.

| Measurement | Direct Copilot mock | Thread mock |
| --- | ---: | ---: |
| BR-INV-01 | PASS | PASS |
| BR-INV-02 | PASS | PASS |
| OpenAPI conformance | PASS | PASS |
| Fixture regression suite | PASS | PASS |
| Session-close recovery | PASS | PASS |
| Wall-clock median (seconds) | 0.537 | 4.384 |
| Scripted credits, chat and worker | 3 | 3 |
| Scripted turns, chat and worker | 3 | 3 |
| Restart to recovered context median (seconds) | 0.0431 | 0.4616 |
| Context rework median (seconds) | 0.000116 | 0.000000 |
| Scripted human interventions | 2 | 3 |

## Per-pair timing

| Pair | Direct wall (s) | Thread wall (s) | Direct restart (s) | Thread restart (s) | Direct rework (s) | Thread rework (s) |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 0.537 | 4.384 | 0.0426 | 0.4625 | 0.000115 | 0.000000 |
| 2 | 0.546 | 4.470 | 0.0431 | 0.4610 | 0.000116 | 0.000000 |
| 3 | 0.535 | 4.341 | 0.0450 | 0.4616 | 0.000118 | 0.000000 |

The incomplete baseline returned BR-INV-01 FAIL, BR-INV-02 FAIL, OpenAPI conformance FAIL as expected. Both final trees ran the unchanged fixture suite.
Direct interventions were resubmitting the request and accepting the candidate into Git.
Thread interventions were the authenticated spec approval, plan approval, and merge.
Direct executed 3 scripted chat actions. Thread executed 2 scripted chat actions and recorded 1 turn in the mock worker's durable usage totals. Each scripted turn consumes one mock credit.

## Live dependencies and expansion

The release closeout diagnostic `thread doctor --spike --require-live` returned exit 2. The organization Copilot CLI, Copilot Business authentication, and the VS Code Copilot Chat extension were unavailable.

Install the organization-approved Copilot CLI and put it on PATH or set `COPILOT_CLI_PATH`. Authenticate with the Copilot Business account, supply the approved SDK credential, and confirm the optional SDK is installed. Install and sign into GitHub Copilot Chat in VS Code with local stdio MCP allowed by organization policy. Re-run `thread doctor --spike --require-live` and follow the matched live protocol in the README once it passes.

The local timings include actual process lifecycle, Git, and fixture work. Thread also runs revision-bound approvals and clean-checkout verification before the final acceptance run. The simulated turns and approvals do not estimate provider billing, live model latency, or human review time. The observed orchestration overhead and persisted spec recovery are useful harness checks. They leave the live cost-benefit comparison and Milestone 3 decisions pending.
