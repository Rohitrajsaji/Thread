"""Trusted verification workflow, ownership template, and ruleset setup."""
INSTALL = r"""      - name: Install the organization's verified Thread release
        shell: bash
        working-directory: ${{ runner.temp }}
        env:
          WHEEL_URL: ${{ vars.THREAD_WHEEL_URL }}
          WHEEL_SHA256: ${{ vars.THREAD_WHEEL_SHA256 }}
        run: |
          set -euo pipefail
          [[ "$WHEEL_SHA256" =~ ^[0-9a-f]{64}$ ]]
          filename="${WHEEL_URL##*/}"
          [[ "$filename" =~ ^thread_sdlc-[0-9A-Za-z._+-]+\.whl$ ]]
          curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' "$WHEEL_URL" -o "$filename"
          echo "$WHEEL_SHA256  $filename" | sha256sum --check
          python -m venv "$RUNNER_TEMP/thread-verify"
          "$RUNNER_TEMP/thread-verify/bin/python" -m pip install "./$filename" pytest
          echo "$RUNNER_TEMP/thread-verify/bin" >> "$GITHUB_PATH"
"""
CHECKOUT = """      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          fetch-depth: 0
          persist-credentials: false
"""
WORKFLOW = """name: Thread verification
on:
  pull_request:
  pull_request_review:
    types: [submitted, dismissed]
permissions:
  contents: read
jobs:
  review:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: read
    outputs:
      revision: ${{ steps.review.outputs.revision }}
      reviewed: ${{ steps.review.outputs.reviewed }}
    steps:
""" + INSTALL + CHECKOUT + """      - id: review
        name: Check protected-file review at this revision
        env:
          GH_TOKEN: ${{ secrets.THREAD_REVIEW_TOKEN || github.token }}
        run: |
          set -euo pipefail
          python -I -m thread_sdlc.governance.review >> "$GITHUB_OUTPUT"
  verify:
    needs: review
    runs-on: ubuntu-latest
    steps:
""" + INSTALL + CHECKOUT + """      - name: Verify the exact proposed commit
        env:
          THREAD_TRUSTED_REVISION: ${{ needs.review.outputs.revision }}
          THREAD_TRUSTED_REVIEW: ${{ needs.review.outputs.reviewed }}
        run: thread verify --ci
"""

OWNERS = """# Replace the example identity with your GitHub code owner before enabling CI.
/.thread/ @YOUR-ORG/thread-maintainers
/.github/workflows/ @YOUR-ORG/thread-maintainers
/.github/CODEOWNERS @YOUR-ORG/thread-maintainers
/src/thread_sdlc/governance/ @YOUR-ORG/thread-maintainers
/src/thread_sdlc/cli/ @YOUR-ORG/thread-maintainers
/scripts/verify* @YOUR-ORG/thread-maintainers
/tests/acceptance/ @YOUR-ORG/thread-maintainers
conftest.py @YOUR-ORG/thread-maintainers
/pytest.ini @YOUR-ORG/thread-maintainers
/.pytest.ini @YOUR-ORG/thread-maintainers
/pytest.toml @YOUR-ORG/thread-maintainers
/.pytest.toml @YOUR-ORG/thread-maintainers
/pyproject.toml @YOUR-ORG/thread-maintainers
/setup.cfg @YOUR-ORG/thread-maintainers
/tox.ini @YOUR-ORG/thread-maintainers
"""

GUIDANCE = """# Thread repository rules

Publish an approved Thread wheel at an immutable HTTPS URL. Set repository
variables THREAD_WHEEL_URL and THREAD_WHEEL_SHA256 to its URL and SHA-256.
Configure the candidate runner with dependencies needed for your project checks.
Keep credentials and privileged setup out of that job.

Assign real users or teams with write access to the protected files in the
base branch's CODEOWNERS. Include every acceptance test named in the rule
map. When team membership is unavailable to the default token, use individual
code owners or set a THREAD_REVIEW_TOKEN secret for the trusted review job.
Use a fine-grained read-only token with organization Members and repository
Metadata and Pull requests access, limited to the relevant organization and
repositories. Alternatively, mint a GitHub App installation token in the
protected review step. Where secrets are unavailable, use individual owners.

On the protected target, require a pull request, code-owner review, dismissal
of stale reviews on new commits, and the Thread verification workflow from a
protected source using an organization ruleset. Prevent bypass by contributors.
A required status name alone cannot establish workflow integrity. The required
workflow and release wheel must be administered outside the change under test.
After approving a change, rerun the required workflow for the same revision if
the organization ruleset does not trigger on pull_request_review.

The review job runs the installed verifier against Git metadata. The test job
runs on a separate disposable GitHub-hosted runner with read-only repository
permission and no organization secrets. The review job checks the active base
rules and open PR revision before passing its base and head pair to the test
job. Protected changes also require an exact-head approval from an eligible
code owner for each path. Unavailable ownership or review data leaves the
change blocked.

[GitHub ruleset workflow setup](https://docs.github.com/en/enterprise-cloud@latest/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/troubleshooting-rules#troubleshooting-ruleset-workflows)
"""


def generate_ci() -> dict[str, str]:
    return {
        ".github/workflows/thread-verify.yml": WORKFLOW,
        ".github/CODEOWNERS": OWNERS,
        ".github/THREAD_RULESETS.md": GUIDANCE,
    }
