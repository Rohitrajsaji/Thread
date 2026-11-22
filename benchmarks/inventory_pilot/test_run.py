import sys
from pathlib import Path

import pytest

import run


@pytest.mark.parametrize("rule_passed", [True, False])
def test_default_command_writes_report_with_gate_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, rule_passed: bool,
) -> None:
    checks = dict.fromkeys([*run.CHECKS, "Fixture regression suite", "Session-close recovery"], True)
    direct = run.Evidence(checks=checks.copy())
    thread = run.Evidence(checks={**checks, "BR-INV-02": rule_passed})
    baseline = dict.fromkeys(run.CHECKS, False)

    monkeypatch.setattr(sys, "argv", ["run.py"])
    monkeypatch.setattr(run, "__file__", str(tmp_path / "run.py"))
    monkeypatch.setattr(run, "git", lambda *_: "fixture-revision")
    monkeypatch.setattr(
        run, "run_pairs",
        lambda *_: ("baseline", "candidate-tree", baseline, [(direct, thread)]),
    )

    assert run.main() == (0 if rule_passed else 1)
    report = (tmp_path / "REPORT.md").read_text(encoding="utf-8")
    expected = "PASS" if rule_passed else "FAIL"
    assert f"**Mock pilot** {expected}" in report
    assert f"| BR-INV-02 | PASS | {expected} |" in report
    assert "**Live Copilot benchmark** BLOCKED" in report
