"""Honest scan-quality accounting (run.json schema 1.1).

``scan_quality`` reports what was actually exercised versus declared —
derived only from observed runtime activity and the model-declared coverage
ledger. Unexercised surfaces stay ``unassessed``; nothing is extrapolated.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from lyrashield.artifacts.quality import SCAN_QUALITY_SCHEMA, build_scan_quality
from lyrashield.artifacts.state import ReportState
from lyrashield.runtime.session_manager import write_egress_policy
from lyrashield.tools.proxy import caido_api
from strix.tools.coverage.tools import hydrate_coverage_from_disk


def _agent_graph(*agents: tuple[str, str]) -> dict[str, Any]:
    return {
        "statuses": dict(agents),
        "names": {agent_id: agent_id for agent_id, _ in agents},
        "metadata": {},
        "parent_of": {},
    }


def test_quality_distinguishes_observed_declared_unassessed() -> None:
    run_record = {
        "run_id": "q1",
        "status": "completed",
        "sandbox_capabilities": {
            "backend": "docker",
            "authorized_hosts": ["app.example.com", "idle.example.com"],
            "capabilities": {"exec": {"status": "supported"}},
            "preflight": {"degradations": [], "failures": []},
        },
    }
    entries = [
        {
            "surface": "https://app.example.com/login",
            "risk_area": "xss",
            "outcome": "no_issue_found",
        },
        {"surface": "declared-only.example.com", "risk_area": "idor", "outcome": "reported"},
    ]
    reports = [{"id": "v1", "endpoint": "https://app.example.com/search", "severity": "high"}]
    decisions = {
        "violations": [
            {
                "at": "2026-01-01 00:00:00 UTC",
                "method": "GET",
                "host": "evil.example.net",
                "url": "https://evil.example.net/",
                "rule": "outside_authorized_scope",
                "reason": "denied",
            }
        ],
        "dropped": 0,
        "admitted_hosts": {"app.example.com": 3},
    }
    doc = build_scan_quality(
        run_record=run_record,
        agent_graph=_agent_graph(("a1", "finished"), ("a2", "crashed")),
        coverage_entries=entries,
        vulnerability_reports=reports,
        scope_decisions=decisions,
    )
    assert doc["schema"] == SCAN_QUALITY_SCHEMA
    assert doc["observed"]["agents_total"] == 2
    assert doc["observed"]["agents_incomplete"] == 1
    assert doc["observed"]["findings_filed"] == 1
    assert doc["observed"]["proxy_requests_admitted"] == 3
    assert doc["observed"]["proxy_requests_denied"] == 1
    assert doc["declared"]["coverage_entries"] == 2

    rows = {row["surface"]: row for row in doc["surfaces"]}
    # Observed + declared + findings on one surface.
    assert rows["app.example.com"]["assessment"] == "observed"
    assert rows["app.example.com"]["admitted_requests"] == 3
    assert rows["app.example.com"]["findings"] == 1
    assert rows["app.example.com"]["declared_coverage_entries"] == 1
    # Declared-only surface stays declared, never upgraded.
    assert rows["declared-only.example.com"]["assessment"] == "declared"
    # An authorized host with no recorded exercise is honestly unassessed.
    assert rows["idle.example.com"]["assessment"] == "unassessed"
    assert "idle.example.com" in doc["unassessed"]
    # A denied destination is evidence of an attempt, not of exercise.
    assert rows["evil.example.net"]["assessment"] == "denied"
    assert rows["evil.example.net"]["denied_requests"] == 1


def test_quality_without_observations_marks_scope_unassessed() -> None:
    doc = build_scan_quality(
        run_record={
            "run_id": "q2",
            "sandbox_capabilities": {"authorized_hosts": ["a.example.com"]},
        },
        agent_graph={},
        coverage_entries=[],
        vulnerability_reports=[],
        scope_decisions=None,
    )
    assert doc["observed"]["agents_total"] == 0
    assert doc["unassessed"] == ["a.example.com"]
    assert doc["surfaces"][0]["assessment"] == "unassessed"


# ---------------------------------------------------------------------------
# run.json wiring
# ---------------------------------------------------------------------------


@pytest.fixture
def state_1_1(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> ReportState:
    monkeypatch.setenv("LYRASHIELD_RUN_RECORD_V1_1", "1")
    monkeypatch.setenv("STRIX_SANDBOX_MODE", "local")
    monkeypatch.chdir(tmp_path)
    caido_api.clear_scope_decisions()
    monkeypatch.delenv("LYRASHIELD_EGRESS_POLICY", raising=False)
    monkeypatch.delenv("STRIX_RUN_ID", raising=False)
    monkeypatch.setattr(caido_api, "_in_container", lambda: True)
    monkeypatch.setattr(caido_api, "_path_on_readonly_mount", lambda _p: True)
    return ReportState(run_name="quality-scan")


def _read_record(state: ReportState) -> dict[str, Any]:
    return json.loads((state.get_run_dir() / "run.json").read_text())


def test_run_record_1_1_carries_quality_and_violations(
    state_1_1: ReportState, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = state_1_1
    state.set_sandbox_capabilities(
        {
            "schema": "lyrashield-sandbox-capabilities/1.0",
            "backend": "docker",
            "authorized_hosts": ["app.example.com"],
            "capabilities": {"exec": {"status": "supported"}},
            "preflight": {"degradations": [], "failures": []},
        }
    )
    # One denied out-of-scope request becomes persisted evidence.
    _mount, host_dir = write_egress_policy("scan-q", {"app.example.com"})
    monkeypatch.setenv("STRIX_RUN_ID", "scan-q")
    monkeypatch.setenv("LYRASHIELD_EGRESS_POLICY", str(Path(host_dir) / "policy.json"))
    with pytest.raises(ValueError, match="outside the recorded authorized scope"):
        caido_api.build_raw_request(
            method="GET", url="https://evil.example.net/", headers={}, body=""
        )

    assert state.save_run_data()
    record = _read_record(state)
    assert record["sandbox_capabilities"]["backend"] == "docker"
    violations = record["scope_violations"]
    assert violations["total"] == 1
    assert violations["entries"][0]["host"] == "evil.example.net"
    quality = record["scan_quality"]
    assert quality["schema"] == SCAN_QUALITY_SCHEMA
    assert quality["observed"]["proxy_requests_denied"] == 1
    denied = {r["surface"] for r in quality["surfaces"] if r["assessment"] == "denied"}
    assert "evil.example.net" in denied


def test_run_record_1_0_omits_quality_fields(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv("LYRASHIELD_RUN_RECORD_V1_1", raising=False)
    monkeypatch.setenv("STRIX_SANDBOX_MODE", "local")
    monkeypatch.chdir(tmp_path)
    state = ReportState(run_name="legacy-quality")
    state.set_sandbox_capabilities(
        {
            "schema": "lyrashield-sandbox-capabilities/1.0",
            "backend": "docker",
            "authorized_hosts": [],
            "capabilities": {},
            "preflight": {"degradations": [], "failures": []},
        }
    )
    assert state.save_run_data()
    record = _read_record(state)
    # Provenance is unconditional; the evidence/quality blocks are 1.1-only.
    assert record["schema_version"] == "1.0"
    assert record["sandbox_capabilities"]["backend"] == "docker"
    assert "scan_quality" not in record
    assert "scope_violations" not in record


def test_scope_violations_persist_across_saves_and_resume(
    state_1_1: ReportState, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = state_1_1
    _mount, host_dir = write_egress_policy("scan-q2", {"app.example.com"})
    monkeypatch.setenv("STRIX_RUN_ID", "scan-q2")
    monkeypatch.setenv("LYRASHIELD_EGRESS_POLICY", str(Path(host_dir) / "policy.json"))

    with pytest.raises(ValueError):
        caido_api.build_raw_request(
            method="GET", url="https://one.example.net/", headers={}, body=""
        )
    assert state.save_run_data()
    with pytest.raises(ValueError):
        caido_api.build_raw_request(
            method="GET", url="https://two.example.net/", headers={}, body=""
        )
    assert state.save_run_data()
    entries = _read_record(state)["scope_violations"]["entries"]
    assert {e["host"] for e in entries} == {"one.example.net", "two.example.net"}

    # Resume: a fresh ReportState over the same run dir keeps prior entries.
    resumed = ReportState(run_name="quality-scan")
    resumed.hydrate_from_run_dir()
    with pytest.raises(ValueError):
        caido_api.build_raw_request(
            method="GET", url="https://three.example.net/", headers={}, body=""
        )
    assert resumed.save_run_data()
    entries = _read_record(resumed)["scope_violations"]["entries"]
    assert {e["host"] for e in entries} == {
        "one.example.net",
        "two.example.net",
        "three.example.net",
    }


def test_quality_surfaces_are_bounded(state_1_1: ReportState) -> None:
    state = state_1_1
    entries = [
        {"surface": f"https://host-{i}.example.com/", "risk_area": "xss", "outcome": "reported"}
        for i in range(300)
    ]
    doc = build_scan_quality(
        run_record=state.run_record,
        agent_graph={},
        coverage_entries=entries,
        vulnerability_reports=[],
        scope_decisions=None,
    )
    assert len(doc["surfaces"]) <= 200


def test_hydrated_ledger_feeds_quality(state_1_1: ReportState) -> None:
    state = state_1_1
    run_dir = state.get_run_dir()
    state_dir = run_dir / ".state"
    state_dir.mkdir(parents=True, exist_ok=True)
    (state_dir / "coverage.json").write_text(
        json.dumps(
            {
                "ab" * 8: {
                    "surface": "https://app.example.com/",
                    "risk_area": "sqli",
                    "outcome": "no_issue_found",
                    "created_at": "2026-01-01 00:00:00 UTC",
                    "agent_name": "recon",
                }
            }
        ),
        encoding="utf-8",
    )
    hydrate_coverage_from_disk(state_dir)
    assert state.save_run_data()
    quality = _read_record(state)["scan_quality"]
    assert quality["declared"]["coverage_entries"] == 1
    assert quality["declared"]["outcomes"] == {"no_issue_found": 1}
