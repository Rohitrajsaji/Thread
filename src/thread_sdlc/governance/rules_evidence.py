"""Observe repository commands and mapped acceptance tests on a fixed checkout."""
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
from xml.etree import ElementTree

from thread_sdlc.config.models import RulesMap


def run_command(argv: list[str], root: Path, home: Path) -> bool:
    env = {
        "PATH": str(Path(sys.executable).parent) + os.pathsep + os.environ.get("PATH", os.defpath),
        "HOME": str(home), "PYTHONDONTWRITEBYTECODE": "1", "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
        "LANG": "C.UTF-8", "CI": "1", "GIT_TERMINAL_PROMPT": "0",
    }
    return subprocess.run(argv, cwd=root, env=env, stdin=subprocess.DEVNULL,
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=300).returncode == 0


def run_configured(command: str, root: Path, home: Path) -> bool:
    # The command belongs to the protected base revision. Support the detector's
    # "&&" chains; never interpolate a changed path or PR field into the shell.
    return run_command(["/bin/sh", "-c", command], root, home)


def observe_rules(root: Path, rules: RulesMap, head: str, home: Path) -> list[dict]:
    root = root.resolve()
    evidence = []
    for rule_id, rule in sorted(rules.rules.items()):
        if rule.command and not rule.test_nodeids:
            ok = run_configured(rule.command, root, home)
            evidence.append(dict(rule_id=rule_id, test_nodeid=rule.command, commit_sha=head,
                                 outcome="passed" if ok else "failed", provenance="observed"))
            continue
        if not rule.test_nodeids:
            evidence.append(dict(rule_id=rule_id, test_nodeid=None, commit_sha=head,
                                 outcome="missing", provenance="unavailable"))
        for nodeid in rule.test_nodeids:
            file = nodeid.split("::")[0]
            valid = not nodeid.startswith("-") and bool(file) and (root/file).resolve().is_relative_to(root) and (root/file).is_file()
            outcome = "missing"
            if valid:
                with TemporaryDirectory() as tmp:
                    report = Path(tmp)/"result.xml"
                    ok = run_command([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
                                      "-o", "addopts=", f"--junitxml={report}", "--", nodeid], root, home)
                    cases = ElementTree.parse(report).findall(".//testcase") if report.exists() else []
                    executed = bool(cases) and all(
                        all(case.find(tag) is None for tag in ("skipped", "error", "failure"))
                        for case in cases
                    )
                    outcome = "passed" if ok and executed else "failed"
            evidence.append(dict(rule_id=rule_id, test_nodeid=nodeid, commit_sha=head, outcome=outcome,
                                 provenance="observed" if valid else "unavailable"))
    return evidence
