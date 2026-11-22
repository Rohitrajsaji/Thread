"""Exercise the release verifier on fresh Git checkouts of the inventory app."""

import json
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from thread_sdlc.cli.main import app
from thread_sdlc.compiler.ci import generate_ci
from thread_sdlc.governance import review


INVENTORY = Path(__file__).resolve().parents[2] / "examples/inventory-app"
GITHUB_REPO = "sample-org/inventory-app"
RULE_EVIDENCE = {
    "BR-INV-01": "tests/acceptance/test_reservations.py::test_last_unit_race",
    "BR-INV-02": "tests/acceptance/test_reservations.py::test_reservation_expiry",
}


def git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=root, capture_output=True, text=True, check=True
    ).stdout.strip()


def commit(root: Path, message: str) -> str:
    git(root, "add", ".")
    git(root, "commit", "-qm", message)
    return git(root, "rev-parse", "HEAD")


@pytest.fixture
def candidate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    for key in (
        "GITHUB_ACTIONS", "GITHUB_EVENT_PATH", "GITHUB_BASE_REF", "GITHUB_REPOSITORY",
        "THREAD_TRUSTED_REVISION", "THREAD_TRUSTED_REVIEW",
    ):
        monkeypatch.delenv(key, raising=False)
    source = tmp_path / "source"
    shutil.copytree(
        INVENTORY, source,
        ignore=shutil.ignore_patterns(".DS_Store", ".pytest_cache", "__pycache__", ".thread-state", ".agents"),
    )
    for name, value in generate_ci().items():
        target = source / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(value.replace("@YOUR-ORG/thread-maintainers", "@maintainer"), encoding="utf-8")
    git(source, "init", "-qb", "main")
    git(source, "config", "user.name", "Inventory CI Fixture")
    git(source, "config", "user.email", "inventory-ci@example.test")
    commit(source, "Protected inventory baseline")
    git(source, "switch", "-qc", "candidate")
    return source


def clean_checkout(source: Path) -> Path:
    checkout = source.parent / "clean"
    git(source.parent, "clone", "--quiet", "--no-local", "--branch", "candidate", str(source), str(checkout))
    assert not git(checkout, "status", "--porcelain")
    assert not (checkout / ".thread-state").exists()
    return checkout


def verify(checkout: Path, *, base: str | None = "origin/main") -> tuple[int, dict]:
    args = ["verify", "--ci", "--repo", str(checkout)]
    if base:
        args += ["--base-ref", base]
    result = CliRunner().invoke(app, args, catch_exceptions=False)
    assert not (checkout / ".thread-state").exists()
    return result.exit_code, json.loads(result.output)


def propose_docs(source: Path, content: str = "Inventory release notes.\n") -> None:
    (source / "release-notes.md").write_text(content, encoding="utf-8")
    commit(source, "Update release notes")


def assert_observed(report: dict, rule_id: str, outcome: str) -> None:
    rows = [row for row in report["rule_evidence"] if row["rule_id"] == rule_id]
    assert rows == [
        {
            "rule_id": rule_id,
            "test_nodeid": RULE_EVIDENCE[rule_id],
            "commit_sha": report["commit_sha"],
            "outcome": outcome,
            "provenance": "observed",
        }
    ]


def test_br_inv_01_concurrent_reservations_pass_in_clean_checkout(candidate: Path) -> None:
    propose_docs(candidate)
    checkout = clean_checkout(candidate)
    code, report = verify(checkout)
    assert code == 0 and report["passed"]
    assert report["commit_sha"] == git(checkout, "rev-parse", "HEAD")
    assert_observed(report, "BR-INV-01", "passed")


def test_br_inv_02_expiry_passes_in_clean_checkout(candidate: Path) -> None:
    propose_docs(candidate)
    code, report = verify(clean_checkout(candidate))
    assert code == 0 and report["passed"]
    assert_observed(report, "BR-INV-02", "passed")


@pytest.mark.parametrize(
    ("rule_id", "before", "after"),
    [
        ("BR-INV-01", "stock[0] - allocated", "stock[0]"),
        ("BR-INV-02", "expires_at <= ?", "expires_at < ?"),
    ],
)
def test_business_rule_failure_blocks_clean_checkout(
    candidate: Path, rule_id: str, before: str, after: str,
) -> None:
    module = candidate / "app/inventory.py"
    text = module.read_text(encoding="utf-8")
    assert text.count(before) == 1
    module.write_text(text.replace(before, after), encoding="utf-8")
    commit(candidate, "Introduce inventory regression")
    code, report = verify(clean_checkout(candidate))
    assert code == 1 and not report["passed"]
    assert rule_id in report["scorecard"]["business_rules"]["issues"]
    assert_observed(report, rule_id, "failed")


@pytest.mark.parametrize(
    "path",
    [
        ".thread/policy.yaml",
        ".thread/scope.yaml",
        ".thread/rules-map.yaml",
        ".github/workflows/thread-verify.yml",
        "src/thread_sdlc/governance/engine.py",
        "tests/acceptance/test_reservations.py",
    ],
)
def test_clean_checkout_blocks_protected_changes_without_approval(candidate: Path, path: str) -> None:
    changed = candidate / path
    changed.parent.mkdir(parents=True, exist_ok=True)
    with changed.open("a", encoding="utf-8") as stream:
        stream.write("\n# Proposed maintenance edit\n")
    commit(candidate, "Propose protected file update")
    code, report = verify(clean_checkout(candidate))
    assert code == 1 and not report["passed"]
    assert report["scorecard"]["protected_files"]["issues"] == [path]
    assert report["rule_evidence"] == []


def test_clean_checkout_rejects_unsubstantiated_claim(candidate: Path) -> None:
    propose_docs(candidate, "<INVENTED> This requirement has no source.\n")
    code, report = verify(clean_checkout(candidate))
    assert code == 1 and not report["passed"]
    assert report["scorecard"]["provenance"]["issues"] == ["release-notes.md"]


def test_clean_checkout_rejects_openapi_break(candidate: Path) -> None:
    contract = candidate / "contracts/openapi.yaml"
    value = yaml.safe_load(contract.read_text(encoding="utf-8"))
    value["paths"]["/inventory/reservations"]["post"]["responses"].pop("201")
    contract.write_text(yaml.safe_dump(value), encoding="utf-8")
    commit(candidate, "Remove success response from candidate contract")
    code, report = verify(clean_checkout(candidate))
    assert code == 1 and not report["passed"]
    assert report["scorecard"]["openapi"]["issues"] == ["Changed response 201 on POST /inventory/reservations"]


def hosted_event(checkout: Path, monkeypatch: pytest.MonkeyPatch, **overrides: str) -> dict:
    base = git(checkout, "rev-parse", "origin/main")
    head = git(checkout, "rev-parse", "HEAD")
    pr = {
        "number": 42,
        "base": {"ref": overrides.get("branch", "main"), "sha": overrides.get("base", base),
                 "repo": {"full_name": GITHUB_REPO}},
        "head": {"sha": overrides.get("head", head)},
        "user": {"login": "change-author"},
    }
    event = checkout.parent / "event.json"
    event.write_text(json.dumps({"pull_request": pr}), encoding="utf-8")
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_REPOSITORY", GITHUB_REPO)
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event))
    monkeypatch.chdir(checkout)
    return pr


def mock_github(
    monkeypatch: pytest.MonkeyPatch, pr: dict, *,
    reviewer: str = "maintainer", permission: str = "write",
    old_review: bool = False, rules_active: bool = True,
    change_requested: bool = False, no_review: bool = False,
    head_current: bool = True, base_current: bool = True,
) -> None:
    def respond(*args: str):
        if args[0] == f"repos/{GITHUB_REPO}/rules/branches/main":
            return [{
                "type": "pull_request",
                "parameters": {"require_code_owner_review": rules_active, "dismiss_stale_reviews_on_push": True},
            }]
        if args[0] == "graphql":
            assert "number=42" in args
            state = {
                "state": "OPEN", "reviewDecision": "CHANGES_REQUESTED" if change_requested else "APPROVED",
                "headRefOid": pr["head"]["sha"] if head_current else "9" * 40,
                "baseRefOid": pr["base"]["sha"] if base_current else "9" * 40,
            }
            return {"data": {"repository": {"pullRequest": state}}}
        if args[-1] == f"repos/{GITHUB_REPO}/pulls/42/reviews?per_page=100":
            sha = pr["base"]["sha"] if old_review else pr["head"]["sha"]
            return [[]] if no_review else [[{"id": 1, "state": "APPROVED", "commit_id": sha, "user": {"login": reviewer}}]]
        if args[0] == f"repos/{GITHUB_REPO}/collaborators/{reviewer}/permission":
            return {"permission": permission}
        pytest.fail(f"Unexpected GitHub API call: {args}")

    monkeypatch.setattr(review, "_api", respond)


def transfer_trusted_receipts(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture) -> dict:
    review.main()
    receipts = dict(line.split("=", 1) for line in capsys.readouterr().out.splitlines())
    workflow = yaml.load(generate_ci()[".github/workflows/thread-verify.yml"], Loader=yaml.BaseLoader)
    review_job, verify_job = (workflow["jobs"][job] for job in ("review", "verify"))
    assert "thread_sdlc.governance.review >> \"$GITHUB_OUTPUT\"" in review_job["steps"][-1]["run"]
    assert verify_job["needs"] == "review"
    assert verify_job["steps"][-1]["run"] == "thread verify --ci"
    assert "GH_TOKEN" not in verify_job["steps"][-1]["env"]
    for key, output in (("THREAD_TRUSTED_REVISION", "revision"), ("THREAD_TRUSTED_REVIEW", "reviewed")):
        assert review_job["outputs"][output] == "${{ steps.review.outputs." + output + " }}"
        assert verify_job["steps"][-1]["env"][key] == "${{ needs.review.outputs." + output + " }}"
        monkeypatch.setenv(key, receipts[output])
    return receipts


@pytest.mark.parametrize(
    ("response", "approved"),
    [
        ({}, True),
        ({"old_review": True}, False),
        ({"reviewer": "other-contributor"}, False),
        ({"permission": "read"}, False),
        ({"change_requested": True}, False),
        ({"no_review": True}, False),
    ],
)
def test_protected_change_requires_exact_current_code_owner_review(
    candidate: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture,
    response: dict, approved: bool,
) -> None:
    policy = candidate / ".thread/policy.yaml"
    with policy.open("a", encoding="utf-8") as stream:
        stream.write("\n# Updated policy explanation\n")
    commit(candidate, "Update policy")
    checkout = clean_checkout(candidate)
    pr = hosted_event(checkout, monkeypatch)
    mock_github(monkeypatch, pr, **response)
    receipts = transfer_trusted_receipts(monkeypatch, capsys)
    assert receipts["reviewed"] == (receipts["revision"] if approved else "")
    code, report = verify(checkout, base=None)
    assert code == (0 if approved else 1)
    assert report["passed"] == approved
    assert report["scorecard"]["protected_files"]["passed"] == approved


@pytest.mark.parametrize(
    ("response", "message"),
    [
        ({"rules_active": False}, "lacks required code-owner"),
        ({"head_current": False}, "no longer reports"),
        ({"base_current": False}, "no longer reports"),
    ],
)
def test_trusted_job_requires_active_rules_and_current_pr_revision(
    candidate: Path, monkeypatch: pytest.MonkeyPatch, response: dict, message: str,
) -> None:
    propose_docs(candidate)
    pr = hosted_event(clean_checkout(candidate), monkeypatch)
    mock_github(monkeypatch, pr, **response)
    with pytest.raises(ValueError, match=message):
        review.main()


def test_hosted_ci_resolves_exact_trusted_base_from_pr(
    candidate: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture,
) -> None:
    propose_docs(candidate)
    checkout = clean_checkout(candidate)
    pr = hosted_event(checkout, monkeypatch)
    mock_github(monkeypatch, pr)
    code, report = verify(checkout, base=None)
    assert code == 1
    assert "did not confirm" in report["scorecard"]["verification_error"]["issues"][0]
    receipts = transfer_trusted_receipts(monkeypatch, capsys)
    assert receipts["revision"] == f"{pr['base']['sha']}:{pr['head']['sha']}"
    assert receipts["reviewed"] == ""
    code, report = verify(checkout, base=None)
    assert code == 0 and report["passed"]
    code, report = verify(checkout, base="HEAD")
    assert code == 1
    assert "Explicit base differs" in report["scorecard"]["verification_error"]["issues"][0]


@pytest.mark.parametrize(("overrides", "message"), [
    ({"head": "9" * 40}, "revisions disagree"),
    ({"branch": "unprotected"}, "branch configured by the base policy"),
])
def test_hosted_event_rejects_checkout_or_base_branch_mismatch(
    candidate: Path, monkeypatch: pytest.MonkeyPatch, overrides: dict, message: str,
) -> None:
    propose_docs(candidate)
    checkout = clean_checkout(candidate)
    hosted_event(checkout, monkeypatch, **overrides)
    code, report = verify(checkout, base=None)
    assert code == 1
    assert message in report["scorecard"]["verification_error"]["issues"][0]
