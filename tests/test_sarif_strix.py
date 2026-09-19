"""Upstream (substrate) SARIF coverage/calibration tests.

Coverage entries and calibration ``properties.strix`` are substrate features
of ``strix.report.sarif``; the owned SARIF contract lives in
``lyrashield.artifacts.sarif`` (test_sarif.py) and is Task 8 scope to extend.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from strix.report.sarif import write_sarif


if TYPE_CHECKING:
    from pathlib import Path


def _read(run_dir: Path) -> dict[str, Any]:
    doc = json.loads((run_dir / "findings.sarif").read_text(encoding="utf-8"))
    assert isinstance(doc, dict)
    return doc


def _finding(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": "vuln-0001",
        "title": "SQL Injection in get_user",
        "severity": "critical",
        "cwe": "CWE-89",
        "timestamp": "2026-07-02 10:00:00 UTC",
        "code_locations": [{"file": "app.py", "start_line": 4}],
    }
    base.update(overrides)
    return base


def _coverage(*entries: dict[str, Any], **overrides: Any) -> dict[str, Any]:
    doc: dict[str, Any] = {
        "entries": list(entries),
        "completeness": {"complete": True, "caveats": []},
    }
    doc.update(overrides)
    return doc


def _coverage_entry(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "surface": "POST /api/orders/{id}",
        "risk_area": "SQL injection",
        "outcome": "no_issue_found",
        "outcome_label": "No issue identified",
        "evidence": "14 parameters fuzzed; all queries parameterized.",
        "recorded_by": "injection-tester",
        "source": "agent_reported",
    }
    base.update(overrides)
    return base


def test_cleared_surface_becomes_a_passing_result(tmp_path: Path) -> None:
    """ "Tested and clean" is a SARIF pass, not an absent result."""
    write_sarif(tmp_path, [], coverage=_coverage(_coverage_entry()))
    results = _read(tmp_path)["runs"][0]["results"]

    assert len(results) == 1
    assert results[0]["kind"] == "pass"
    # SARIF requires level "none" on any result that is not a failure.
    assert results[0]["level"] == "none"
    assert "14 parameters fuzzed" in results[0]["message"]["text"]


def test_coverage_outcomes_map_to_their_sarif_kinds(tmp_path: Path) -> None:
    write_sarif(
        tmp_path,
        [],
        coverage=_coverage(
            _coverage_entry(outcome="ruled_out", risk_area="XSS"),
            _coverage_entry(outcome="not_applicable", risk_area="XXE"),
            _coverage_entry(outcome="needs_follow_up", risk_area="SSRF"),
        ),
    )
    kinds = [result["kind"] for result in _read(tmp_path)["runs"][0]["results"]]

    assert kinds == ["pass", "notApplicable", "open"]


def test_reported_coverage_is_not_duplicated_as_a_pass(tmp_path: Path) -> None:
    """A surface that produced a finding is already in results as a failure."""
    write_sarif(
        tmp_path,
        [_finding()],
        coverage=_coverage(_coverage_entry(outcome="reported")),
    )
    results = _read(tmp_path)["runs"][0]["results"]

    assert len(results) == 1
    assert results[0].get("kind", "fail") == "fail"


def test_coverage_results_declare_their_own_rules(tmp_path: Path) -> None:
    write_sarif(
        tmp_path,
        [_finding()],
        coverage=_coverage(
            _coverage_entry(risk_area="SQL injection"),
            _coverage_entry(risk_area="SQL injection", surface="GET /search"),
        ),
    )
    run = _read(tmp_path)["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    coverage_rules = [rule for rule in rules if rule["id"].startswith("strix-coverage/")]

    # Both entries share one rule, and every result's ruleIndex resolves to it.
    assert len(coverage_rules) == 1
    assert coverage_rules[0]["defaultConfiguration"]["level"] == "none"
    for result in run["results"]:
        assert rules[result["ruleIndex"]]["id"] == result["ruleId"]


def test_incomplete_run_is_flagged_on_the_invocation(tmp_path: Path) -> None:
    """A scan cut short must not be indistinguishable from a clean one."""
    write_sarif(
        tmp_path,
        [],
        coverage=_coverage(
            _coverage_entry(),
            completeness={"complete": False, "caveats": ["Budget exhausted."]},
        ),
    )
    invocation = _read(tmp_path)["runs"][0]["invocations"][0]

    assert invocation["executionSuccessful"] is False
    assert invocation["toolExecutionNotifications"][0]["message"]["text"] == "Budget exhausted."


def test_complete_run_reports_a_successful_invocation(tmp_path: Path) -> None:
    write_sarif(tmp_path, [], coverage=_coverage(_coverage_entry()))
    invocation = _read(tmp_path)["runs"][0]["invocations"][0]

    assert invocation["executionSuccessful"] is True
    assert "toolExecutionNotifications" not in invocation


def test_calibration_metadata_survives_into_result_properties(tmp_path: Path) -> None:
    write_sarif(
        tmp_path,
        [
            _finding(
                confidence="medium",
                counterevidence="WAF blocks the naive payload.",
                confidence_rationale="Reproduced once out of three attempts.",
                severity_change_conditions="Critical if the WAF rule is removed.",
                fix_verification="Not retested.",
            )
        ],
    )
    strix = _read(tmp_path)["runs"][0]["results"][0]["properties"]["strix"]

    assert strix["confidence"] == "medium"
    assert strix["counterevidence"] == "WAF blocks the naive payload."
    assert strix["confidence_rationale"] == "Reproduced once out of three attempts."
    assert strix["severity_change_conditions"] == "Critical if the WAF rule is removed."
    assert strix["fix_verification"] == "Not retested."
