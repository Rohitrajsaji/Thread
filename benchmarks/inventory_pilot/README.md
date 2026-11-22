# INV-101 pilot

Run from the Thread checkout with the development dependencies installed.

```sh
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python benchmarks/inventory_pilot/run.py
```

The command runs three pairs and writes `REPORT.md` beside the runner. Use `--report` to save to another path and `--fixture-revision` to select a different committed fixture. Each pair starts with independent clones of one Git commit. The runner archives the committed inventory fixture, keeps the story, OpenAPI contract, and acceptance tests, and replaces the POST handler body with HTTP 501. The reference handler supplies identical scripted changes to both arms. Both business rules and runtime contract tests must fail on that incomplete baseline. The final Git trees must match and differ from the baseline only in `app/inventory.py`.

The Direct Copilot mock process reads the request and its artifacts in memory. The pilot terminates that process before implementation and opens a new one. The operator script resubmits the request and verifies the recovered context fingerprint before the candidate is written. In the Thread arm a real MCP subprocess records the pending spec and closes. While it is closed, the local reviewer approves the spec over the authenticated Approval API. A fresh MCP process retrieves the exact revision and approval. The remaining work uses the real Thread plan, mock worker, verification, and human-authorized merge paths. Both final checkouts run the same fixture tests and record per-test results.

Wall time covers each arm from the first session through acceptance verification. Recovery time starts when the new session launches and ends when it confirms the recovered context or revision. Thread's scripted approval while the session is closed counts towards total wall time. Rework measures repeated task-context reads in the Direct process. The Thread arm resumes without replaying the spec. Human intervention counts reflect the explicit mock operator actions. One scripted turn is assigned one mock credit, including the Thread mock worker turn. The recorded data carries no provider usage or live human review timings.

The default report and pass/fail exit status have focused unit checks.

```sh
PYTHONDONTWRITEBYTECODE=1 .venv/bin/pytest -p no:cacheprovider benchmarks/inventory_pilot/test_run.py
```

## Manual live protocol

1. On an organization-managed device, install the approved Copilot CLI and authenticate it with a Copilot Business account. Install the optional Thread Copilot SDK and supply an approved credential through the organization's secret-handling process. Install and sign into the VS Code Copilot Chat extension and confirm local stdio MCP is allowed. Run `thread doctor --spike --require-live` and retain the redacted output. Proceed after it confirms the runtime is available.
2. Create fresh checkouts outside the Thread repository for every pair. Use the report's fixture source revision if rerunning an existing comparison.

   ```sh
   pilot_workspace="$(mktemp -d /tmp/thread-inventory-live.XXXXXXXX)"
   PYTHONDONTWRITEBYTECODE=1 .venv/bin/python benchmarks/inventory_pilot/run.py \
     --prepare-live "$pilot_workspace/pair"
   ```

3. Open `pair/direct` and `pair/thread` in separate VS Code windows. Run `thread init` in the Thread checkout to install its agent and MCP instructions. Select the same model and use the same account, repository permissions, and time budget for both arms. Start a new chat each time. Alternate which arm runs first across pairs.
4. Give each arm the request below and provide the same story and contract. Use normal Copilot Chat in Direct and `@thread` in Thread. Close the VS Code window after each arm has produced its first specification, before either edits the source. Record when the window closes, what context and work survives, and when an equivalent new session is ready to implement. In Thread approve the pending spec from the local Approval Web UI while the editor is closed, then reopen the workspace and resume. In Direct reopen the workspace, recover prior work available to the operator, and record any context resubmission. Complete the remaining work and record every approval and manual correction.

   > Implement INV-101 Inventory Reservations using the story and OpenAPI contract. Use `docs/stories/INV-101.md` and `contracts/openapi.yaml` as inputs.

5. On each final commit run the same fixture suite and retain JUnit output outside the checkout. Record the final commit and the two business-rule outcomes, OpenAPI conformance, and the entire fixture suite result. For Thread also retain the verified revision and final review receipt.

   ```sh
   PYTHONDONTWRITEBYTECODE=1 python -m pytest -p no:cacheprovider -q \
     --junitxml "$pilot_workspace/thread-results.xml"
   ```

   Run from each checkout with its development dependencies available and use a separate XML path for each arm.

6. Record elapsed wall time, elapsed recovery and duplicated work time, each manual intervention, and all Chat and Worker turns. Capture provider or seat usage at the start and end of each arm in an otherwise idle accounting window. Record the observed delta, source, and granularity. Mark usage unavailable when the provider cannot attribute it to an arm. Keep raw redacted diagnostic and usage evidence outside the checkout. Compare paired observations by arm and record any workflow failure or bottleneck.
7. Keep the generated mock rows in `REPORT.md` and add a separate live results section using the same metric headings and links to redacted evidence. Update live readiness only once observed results support it. Use the measured bottlenecks to decide whether any Milestone 3 module is warranted.
