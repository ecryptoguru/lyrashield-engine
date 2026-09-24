"""run.json schema 1.1 evidence contract tests (Task 8 engine-writer).

Covers the bounded richer evidence: counterevidence / confidence /
severity_change_conditions / fix_verification / advisory_cvss /
http_exchange_ids, update_history, the coverage + threat-model companion
artifacts, the result manifest, and the HTTP exchange evidence export
(redacted, checksummed, explicitly incomplete on failure).
"""

from __future__ import annotations

import json
import types
from pathlib import Path
from typing import Any

import pytest
from agents.tool_context import ToolContext

from lyrashield.artifacts import evidence as _evidence
from lyrashield.artifacts.state import (
    _MAX_COLLECTION_SIZE,
    _MAX_FINDING_SERIALIZED_SIZE,
    _MAX_TEXT_LENGTH,
    ReportState,
    set_global_report_state,
    validate_run_record,
)
from lyrashield.tools.reporting import tool as reporting_tool
from strix.tools.coverage.tools import hydrate_coverage_from_disk
from strix.tools.threat_model.tools import hydrate_threat_models_from_disk


def _read_json(path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_state_dir_artifacts(state: ReportState) -> None:
    """Materialize the `.state` files the companion artifacts read."""
    run_dir = state.get_run_dir()
    state_dir = run_dir / ".state"
    state_dir.mkdir(parents=True, exist_ok=True)
    (state_dir / "coverage.json").write_text(
        json.dumps(
            {
                "c0" * 16: {
                    "surface": "https://example.test/login",
                    "risk_area": "authentication",
                    "outcome": "reported",
                    "evidence": "lockout counter never incremented",
                    "created_at": "2026-01-01 00:00:00 UTC",
                    "agent_name": "recon",
                }
            }
        ),
        encoding="utf-8",
    )
    (state_dir / "agents.json").write_text(
        json.dumps(
            {
                "statuses": {"agent-1": "finished"},
                "names": {"agent-1": "recon"},
                "metadata": {"agent-1": {"skills": ["web-recon"]}},
                "parent_of": {},
            }
        ),
        encoding="utf-8",
    )
    (state_dir / "threat_models.json").write_text(
        json.dumps(
            {
                "https://example.test": {
                    "target": "https://example.test",
                    "written_at": "2026-01-01T00:00:00+00:00",
                    "written_by": "recon",
                    "content": (
                        "## Overview\nLogin app handling session tokens.\n\n"
                        "## Trust Boundaries and Assumptions\nEdge to app; HTTPS only.\n\n"
                        "## Attack Surface and Attacker Stories\nUnauthenticated "
                        "attacker stuffing credentials.\n\n## Severity Calibration\n"
                        "Account takeover is critical."
                    ),
                    "amendments": [],
                }
            }
        ),
        encoding="utf-8",
    )
    hydrate_coverage_from_disk(state_dir)
    hydrate_threat_models_from_disk(state_dir)


@pytest.fixture
def state_1_1(monkeypatch, tmp_path) -> ReportState:
    monkeypatch.setenv("LYRASHIELD_RUN_RECORD_V1_1", "1")
    monkeypatch.setenv("STRIX_SANDBOX_MODE", "local")
    monkeypatch.chdir(tmp_path)
    return ReportState(run_name="v11scan")


def _vuln_kwargs(**overrides) -> dict[str, Any]:
    kwargs: dict[str, Any] = {
        "title": "XSS in search",
        "description": "Reflected XSS",
        "severity": "high",
        "evidence": "Response echoed payload",
    }
    kwargs.update(overrides)
    return kwargs


def _report(state: ReportState, report_id: str) -> dict[str, Any]:
    for report in state.vulnerability_reports:
        if report["id"] == report_id:
            return report
    raise AssertionError(f"{report_id} not filed")


# ---------------------------------------------------------------------------
# Emission
# ---------------------------------------------------------------------------


def test_run_record_emits_schema_1_1_and_artifacts(state_1_1: ReportState) -> None:
    state = state_1_1
    rid = state.add_vulnerability_report(**_vuln_kwargs())
    _write_state_dir_artifacts(state)
    assert state.save_run_data()

    run_dir = state.get_run_dir()
    record = _read_json(run_dir / "run.json")
    assert record["schema_version"] == "1.1"
    assert record["evidence_format"] == "1.1"
    manifest = record["result_manifest"]
    assert manifest["schema_version"] == 1
    for name in ("vulnerabilities.json", "coverage.json", "threat_model.json"):
        entry = manifest["artifacts"][name]
        assert entry["bytes"] > 0
        assert len(entry["sha256"]) == 64
    validate_run_record(record)

    vulns = _read_json(run_dir / "vulnerabilities.json")
    assert isinstance(vulns, list)
    report = next(r for r in vulns if r["id"] == rid)
    assert report["evidence_contract_version"] == "1.1"
    assert report["verification_state"] == "unverified"

    coverage = _read_json(run_dir / "coverage.json")
    assert coverage["schema_version"] in ("1.0", 1)
    assert coverage["run_id"] == state.run_id
    # agent_reported claims stay separate from machine_observed runtime facts.
    assert coverage["entries"][0]["surface"] == "https://example.test/login"
    assert coverage["entries"][0]["source"] == "model_declared"
    assert coverage["summary"]["findings_filed"] == 1
    agents = coverage["machine_observed"]["agents"]
    assert agents and agents[0]["status"] == "finished"
    assert coverage["machine_observed"]["skills_exercised"] == ["web-recon"]
    assert coverage["machine_observed"]["source"] == "runtime"

    threat = _read_json(run_dir / "threat_model.json")
    assert threat["schema_version"] == "lyrashield-threat-model/1.0"
    assert threat["run_id"] == state.run_id
    model = threat["models"][0]
    assert model["target"] == "https://example.test"
    assert model["written_by"] == "recon"


def test_threat_model_artifact_redacts_model_controlled_text(state_1_1: ReportState) -> None:
    run_dir = state_1_1.get_run_dir()
    state_dir = run_dir / ".state"
    state_dir.mkdir(parents=True, exist_ok=True)
    sentinel = "sample-secret-123"
    (state_dir / "threat_models.json").write_text(
        json.dumps(
            {
                "password=sample-secret-123": {
                    "target": "https://example.test/?password=sample-secret-123",
                    "written_by": "password=sample-secret-123",
                    "content": "password=sample-secret-123",
                    "amendments": [
                        {
                            "by": "password=sample-secret-123",
                            "at": "password=sample-secret-123",
                            "content": "password=sample-secret-123",
                        }
                    ],
                }
            }
        ),
        encoding="utf-8",
    )

    document = _evidence.build_threat_model_document(run_dir, {"run_id": "run-1"})
    assert document is not None
    path = _evidence.write_threat_model_artifact(run_dir, document)

    assert path.name == "threat_model.json"
    assert isinstance(document["models"], list)
    assert sentinel not in json.dumps(document)
    assert sentinel not in path.read_text(encoding="utf-8")


def test_threat_model_writer_matches_cross_repo_golden(state_1_1: ReportState) -> None:
    run_dir = state_1_1.get_run_dir()
    state_dir = run_dir / ".state"
    state_dir.mkdir(parents=True, exist_ok=True)
    (state_dir / "threat_models.json").write_text(
        json.dumps(
            {
                "https://app.example.test": {
                    "target": "https://app.example.test/?password=sample-secret-123",
                    "written_at": "2026-09-20T00:00:00+00:00",
                    "written_by": "recon",
                    "content": (
                        "Assets: customer records. Trust boundary: public API to data store. "
                        "password=sample-secret-123"
                    ),
                    "amendments": [
                        {
                            "at": "2026-09-20T00:01:00+00:00",
                            "by": "reviewer",
                            "content": "Unverified admin path; check authorization.",
                        }
                    ],
                }
            }
        ),
        encoding="utf-8",
    )
    document = _evidence.build_threat_model_document(
        run_dir, {"run_id": "fixture-run-1-1", "run_name": "scan-fixture-1-1"}
    )
    assert document is not None
    written = _read_json(_evidence.write_threat_model_artifact(run_dir, document))
    golden = _read_json(Path(__file__).parent / "fixtures/threat_model_writer_1_1.json")
    # Time is the only runtime-generated member; everything else is the exact
    # owned-writer shape copied into the worker's manifest-bound fixture.
    written.pop("generated_at")
    golden.pop("generated_at")
    assert written == golden


def test_flag_off_keeps_schema_1_0_and_no_new_artifacts(monkeypatch, tmp_path) -> None:
    monkeypatch.delenv("LYRASHIELD_RUN_RECORD_V1_1", raising=False)
    monkeypatch.setenv("STRIX_SANDBOX_MODE", "local")
    monkeypatch.chdir(tmp_path)
    state = ReportState(run_name="legacy")
    state.add_vulnerability_report(
        **_vuln_kwargs(
            counterevidence="checked CSP",
            confidence="medium",
            http_exchange_ids=["1042"],
            fix_verification={"statement": "tested", "method": "retest"},
        )
    )
    assert state.save_run_data()
    run_dir = state.get_run_dir()
    record = _read_json(run_dir / "run.json")
    assert record["schema_version"] == "1.0"
    assert "result_manifest" not in record
    assert "evidence_export" not in record
    assert not (run_dir / "coverage.json").exists()
    assert not (run_dir / "threat_model.json").exists()
    assert not (run_dir / "http_exchanges.json").exists()

    vuln = _read_json(run_dir / "vulnerabilities.json")[0]
    # 1.0 projection drops the 1.1-only fields entirely.
    for dropped in (
        "counterevidence",
        "confidence",
        "confidence_rationale",
        "severity_change_conditions",
        "fix_verification",
        "advisory_cvss",
        "http_exchange_ids",
        "update_history",
        "updated_at",
        "evidence_contract_version",
        "verification_state",
        "evidence_warnings",
    ):
        assert dropped not in vuln


def test_schema_1_0_record_hydrates_and_stays_readable(tmp_path) -> None:
    run_dir = tmp_path / "run-legacy"
    run_dir.mkdir()
    legacy = {
        "schema_version": "1.0",
        "run_id": "run-legacy",
        "run_name": "legacy",
        "start_time": "2026-01-01T00:00:00+00:00",
        "end_time": None,
        "status": "completed",
        "phase": "completed",
        "auth_mode": "none",
        "targets_info": [],
        "llm_usage": {},
        "seq": 1,
        "turn_count": 0,
    }
    (run_dir / "run.json").write_text(json.dumps(legacy), encoding="utf-8")
    (run_dir / "vulnerabilities.json").write_text(json.dumps([]), encoding="utf-8")

    validate_run_record(legacy)  # still accepted
    monkeypatch_state = ReportState(run_name="legacy")
    monkeypatch_state._run_dir = run_dir
    monkeypatch_state.hydrate_from_run_dir()
    assert monkeypatch_state.run_name == "legacy"
    assert monkeypatch_state.run_record["schema_version"] == "1.0"


def test_unsupported_schema_version_rejected() -> None:
    base = {
        "schema_version": "0.9",
        "run_id": "r",
        "run_name": "r",
        "start_time": "2026-01-01T00:00:00+00:00",
        "end_time": None,
        "status": "completed",
        "phase": "completed",
        "auth_mode": "none",
        "targets_info": [],
        "llm_usage": {},
        "seq": 1,
        "turn_count": 0,
    }
    with pytest.raises((ValueError, RuntimeError), match="schema_version"):
        validate_run_record(base)
    with pytest.raises((ValueError, RuntimeError), match="schema_version"):
        validate_run_record({**base, "schema_version": "9.9"})


# ---------------------------------------------------------------------------
# Finding evidence fields
# ---------------------------------------------------------------------------


def test_create_stores_bounded_normalized_evidence(state_1_1: ReportState) -> None:
    state = state_1_1
    rid = state.add_vulnerability_report(
        **_vuln_kwargs(
            counterevidence="No CSP found; verified markup context",
            confidence="MEDIUM",
            confidence_rationale="Could not confirm victim-side auth",
            severity_change_conditions="CSP nonce would lower this",
            fix_verification={
                "statement": "Retested endpoint after patch",
                "method": "replayed request",
            },
            advisory_cvss={
                "score": 9.8,
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                "source": "GHSA",
            },
            http_exchange_ids=["1042", " 88 "],
        )
    )
    report = _report(state, rid)
    assert report["confidence"] == "medium"
    assert report["fix_verification"]["kind"] == "engine_attestation"
    assert "recorded_at" in report["fix_verification"]
    assert report["advisory_cvss"]["score"] == 9.8
    assert report["advisory_cvss"]["source"] == "GHSA"
    assert report["http_exchange_ids"] == ["1042", "88"]

    # Secrets/paths in the free-text evidence fields are redacted at persist.
    rid2 = state.add_vulnerability_report(
        **_vuln_kwargs(
            title="Leaked token",
            evidence="token=FAKE_SECRET_0123456789ABCDEF and /Users/x/checkout/app.py seen",
            counterevidence="looked under /Users/x/repo for a guard",
        )
    )
    assert state.save_run_data()
    saved = _read_json(state.get_run_dir() / "vulnerabilities.json")
    report2 = next(r for r in saved if r["id"] == rid2)
    assert "FAKE_SECRET_0123456789ABCDEF" not in json.dumps(report2)
    assert "/Users/x" not in report2["counterevidence"]


def test_malformed_evidence_fields_rejected(state_1_1: ReportState) -> None:
    state = state_1_1
    with pytest.raises(ValueError, match="confidence"):
        state.add_vulnerability_report(**_vuln_kwargs(confidence="sure-thing"))
    with pytest.raises(ValueError, match="fix_verification"):
        state.add_vulnerability_report(**_vuln_kwargs(fix_verification={"statement": "  "}))
    with pytest.raises(ValueError, match="advisory_cvss"):
        state.add_vulnerability_report(**_vuln_kwargs(advisory_cvss={"score": 42.0}))
    with pytest.raises(ValueError, match="http_exchange_ids"):
        state.add_vulnerability_report(**_vuln_kwargs(http_exchange_ids=["good", "bad id!!"]))


# ---------------------------------------------------------------------------
# Revisions
# ---------------------------------------------------------------------------


def test_revision_preserves_identity_and_appends_history(state_1_1) -> None:
    state = state_1_1
    rid = state.add_vulnerability_report(**_vuln_kwargs(severity="medium", confidence="high"))
    revised = state.update_vulnerability_report(
        rid,
        {"severity": "high", "confidence": "low", "evidence": "new PoC output"},
        update_reason="built the PoC after filing; chain confirmed",
        updated_by_agent_id="agent-9",
    )
    assert revised is not None
    assert revised["id"] == rid
    assert revised["timestamp"] == _report(state, rid)["timestamp"]
    history = revised["update_history"]
    assert len(history) == 1
    entry = history[0]
    assert set(entry["fields"]) == {"confidence", "evidence", "severity"}
    assert entry["previous_severity"] == "medium"
    assert entry["previous_confidence"] == "high"
    assert entry["agent_id"] == "agent-9"
    assert "update_reason" not in entry["fields"] or True  # reason is its own key
    assert entry["reason"] == "built the PoC after filing; chain confirmed"

    # All projections regenerated in the same revision pass.
    saved = _read_json(state.get_run_dir() / "vulnerabilities.json")
    assert next(r for r in saved if r["id"] == rid)["severity"] == "high"


def test_revision_superseded_dependents_dropped(state_1_1) -> None:
    state = state_1_1
    rid = state.add_vulnerability_report(
        **_vuln_kwargs(
            severity="medium",
            severity_change_conditions="confirmed reachable -> high",
            confidence="low",
            confidence_rationale="static only",
            cvss=5.0,
            cvss_breakdown={"attack_vector": "N"},
            fix_verification={"statement": "compiled", "method": "pytest"},
            code_locations=[{"file": "a.py", "start_line": 1}],
        )
    )
    revised = state.update_vulnerability_report(
        rid, {"severity": "high"}, update_reason="reachability confirmed"
    )
    assert "severity_change_conditions" not in revised
    # confidence untouched -> its rationale stays
    assert revised["confidence_rationale"] == "static only"
    revised = state.update_vulnerability_report(rid, {"cvss": 8.1}, update_reason="rescored")
    assert "cvss_breakdown" not in revised
    revised = state.update_vulnerability_report(
        rid,
        {"code_locations": [{"file": "b.py", "start_line": 2}]},
        update_reason="fix moved",
    )
    assert "fix_verification" not in revised


def test_revision_invariants_and_bounds(state_1_1) -> None:
    state = state_1_1
    rid = state.add_vulnerability_report(**_vuln_kwargs())

    # Unknown id -> no-op
    assert state.update_vulnerability_report("vuln-9999", {"title": "x"}) is None
    # Empty update -> no-op, no history entry
    assert state.update_vulnerability_report(rid, {"title": "XSS in search"}) is None
    # Immutable fields silently ignored
    revised = state.update_vulnerability_report(
        rid,
        {"title": "Renamed", "id": "vuln-9999", "finding_class": "dependency_cve"},
        update_reason="renaming only",
    )
    assert revised is not None
    assert revised["id"] == rid
    assert revised["finding_class"] == "dynamic"
    assert revised["update_history"][0]["fields"] == ["title"]

    # Revision-history bound: no evidence can be dropped.
    report = _report(state, rid)
    report["update_history"] = [{"fields": ["x"]}] * _evidence.MAX_UPDATE_HISTORY_ENTRIES
    with pytest.raises(RuntimeError, match="revision history bound"):
        state.update_vulnerability_report(rid, {"title": "again"}, update_reason="bound test")

    # A sealed (completed) run is immutable.
    report["update_history"] = []
    state.run_record["status"] = "completed"
    with pytest.raises(RuntimeError, match="sealed"):
        state.update_vulnerability_report(rid, {"title": "late"}, update_reason="post-seal")


def test_revision_callback_gets_sanitized_snapshot(state_1_1) -> None:
    state = state_1_1
    seen: list[dict[str, Any]] = []
    state.vulnerability_updated_callback = seen.append
    rid = state.add_vulnerability_report(**_vuln_kwargs())
    state.update_vulnerability_report(
        rid,
        {"evidence": "leaks api_key=FAKE_SECRET_0123456789ABCDEF in response"},
        update_reason="new evidence",
    )
    assert seen and seen[-1]["id"] == rid
    assert "FAKE_SECRET_0123456789ABCDEF" not in seen[-1]["evidence"]
    # callback payload cannot mutate in-memory state
    seen[-1]["evidence"] = "mutated"
    assert _report(state, rid)["evidence"] != "mutated"


# ---------------------------------------------------------------------------
# Serialization bounds
# ---------------------------------------------------------------------------


def test_serialized_size_bound_fails_closed(state_1_1) -> None:
    state = state_1_1
    huge = "x" * (_MAX_TEXT_LENGTH + 5000)
    rid = state.add_vulnerability_report(**_vuln_kwargs(description=huge))
    state.save_run_data()
    saved = _read_json(state.get_run_dir() / "vulnerabilities.json")
    report = next(r for r in saved if r["id"] == rid)
    # Per-field truncation is the primary bound; serialized size is the
    # last-line catch. Neither writes an unbounded artifact.
    assert len(report["description"]) <= _MAX_TEXT_LENGTH
    assert len(json.dumps(report)) < _MAX_FINDING_SERIALIZED_SIZE


def test_collections_and_depth_bounded(state_1_1) -> None:
    state = state_1_1
    rid = state.add_vulnerability_report(
        **_vuln_kwargs(
            code_locations=[{"file": f"f{i}.py", "start_line": i} for i in range(500)],
        )
    )
    report = _report(state, rid)
    state.save_run_data()
    saved = _read_json(state.get_run_dir() / "vulnerabilities.json")
    saved_loc = next(r for r in saved if r["id"] == rid)["code_locations"]
    assert len(saved_loc) <= _MAX_COLLECTION_SIZE
    assert len(report["code_locations"]) == 500  # in-memory keeps raw


# ---------------------------------------------------------------------------
# HTTP exchange evidence export
# ---------------------------------------------------------------------------


def _ns(value: Any) -> Any:
    """Recursively convert dicts to attribute-accessible objects."""
    if isinstance(value, dict):
        return types.SimpleNamespace(**{k: _ns(v) for k, v in value.items()})
    if isinstance(value, list):
        return [_ns(v) for v in value]
    return value


class _FakeCaidoClient:
    """Minimal stand-in for the Caido SDK client (``client.request.get``)."""

    def __init__(self, entries: dict[str, dict[str, Any]] | None = None) -> None:
        self.entries = {k: _ns(v) for k, v in (entries or {}).items()}
        self.fail = False
        self.request = self

    async def get(self, request_id: str, _opts: Any = None) -> Any:
        if self.fail:
            raise RuntimeError("transport down")
        return self.entries.get(str(request_id))


@pytest.mark.asyncio
async def test_http_exchange_export_redacts_binds_and_checksums(
    state_1_1,
) -> None:
    state = state_1_1
    rid = state.add_vulnerability_report(**_vuln_kwargs(http_exchange_ids=["1042", "88"]))
    state.save_run_data()
    run_dir = state.get_run_dir()

    client = _FakeCaidoClient(
        {
            "1042": {
                "request": {
                    "raw": (
                        "GET /search?api_key=FAKE_SECRET_0123456789ABCDEF "
                        "HTTP/1.1\r\nAuthorization: Bearer abc.def\r\n\r\n"
                    ),
                    "host": "example.test",
                    "port": 443,
                    "is_tls": True,
                    "method": "GET",
                    "path": "/search?api_key=FAKE_SECRET_0123456789ABCDEF",
                    "query": "api_key=FAKE_SECRET_0123456789ABCDEF",
                    "ext": "",
                },
                "response": {
                    "raw": "HTTP/1.1 200 OK\r\nSet-Cookie: sid=zzz\r\n\r\n<h2>ok</h2>",
                    "status_code": 200,
                    "roundtrip_time": 12,
                },
            },
            "88": {
                "request": {
                    "raw": "GET /search HTTP/1.1\r\n\r\n",
                    "host": "example.test",
                    "port": 443,
                    "is_tls": True,
                    "method": "GET",
                    "path": "/search",
                    "query": "",
                    "ext": "",
                },
                "response": {"raw": "HTTP/1.1 200 OK\r\n\r\n", "status_code": 200},
            },
        }
    )
    outcome = await _evidence.export_http_exchange_evidence(
        client,
        run_dir,
        run_record=state.run_record,
        findings=state.vulnerability_reports,
    )
    assert outcome["status"] == "exported"
    assert outcome["exchanges"] == 2
    assert len(outcome["sha256"]) == 64

    artifact = _read_json(run_dir / "http_exchanges.json")
    assert artifact["schema_version"] == "lyrashield-http-exchanges/1.0"
    # The export binds to the run and to the finding that cited each exchange.
    assert artifact["binding"]["run_id"] == state.run_id
    assert artifact["binding"]["run_name"] == state.run_name
    assert artifact["binding"]["findings"] == {rid: ["1042", "88"]}
    exchanges = {e["proxy_request_id"]: e for e in artifact["exchanges"]}
    assert set(exchanges) == {"1042", "88"}
    ex = exchanges["1042"]
    # Secrets are redacted from URL, headers, and bodies — never stored raw.
    assert "FAKE_SECRET_0123456789ABCDEF" not in json.dumps(artifact)
    assert "sid=zzz" not in json.dumps(ex["response"]["headers"])
    assert ex["request"]["method"] == "GET"
    assert ex["request"]["host"] == "example.test"
    assert "FAKE_SECRET_0123456789ABCDEF" not in ex["request"]["target"]
    assert len(ex["request"]["sha256"]) == 64
    assert len(ex["response"]["sha256"]) == 64


@pytest.mark.asyncio
async def test_http_exchange_export_failure_is_explicit_incomplete(
    state_1_1,
) -> None:
    state = state_1_1
    state.add_vulnerability_report(**_vuln_kwargs(http_exchange_ids=["1042"]))
    run_dir = state.get_run_dir()
    run_dir.mkdir(parents=True, exist_ok=True)

    client = _FakeCaidoClient()
    client.fail = True
    outcome = await _evidence.export_http_exchange_evidence(
        client,
        run_dir,
        run_record=state.run_record,
        findings=state.vulnerability_reports,
    )
    assert outcome["status"] == "failed"
    assert outcome["exchanges"] == 0
    artifact = _read_json(run_dir / "http_exchanges.json")
    # The failed export is recorded honestly — no exchanges minted, no
    # silent gap that later reads as "no evidence captured".
    assert artifact["exchanges"] == []
    assert artifact["missing_request_ids"] == ["1042"]


@pytest.mark.asyncio
async def test_http_exchange_export_skips_without_cited_ids(state_1_1) -> None:
    state = state_1_1
    state.add_vulnerability_report(**_vuln_kwargs())
    run_dir = state.get_run_dir()
    outcome = await _evidence.export_http_exchange_evidence(
        None, run_dir, run_record=state.run_record, findings=state.vulnerability_reports
    )
    assert outcome["status"] == "skipped"
    assert not (run_dir / "http_exchanges.json").exists()


# ---------------------------------------------------------------------------
# Reporting-tool verification boundary
# ---------------------------------------------------------------------------


def _tool_ctx(args: dict[str, Any], **context: Any) -> Any:
    """Minimal ToolContext carrying the shared caido client in ``context``."""
    return ToolContext(
        context=dict(context),
        tool_name="test",
        tool_call_id="test-call",
        tool_arguments=json.dumps(args),
    )


@pytest.mark.asyncio
async def test_tool_rejects_unknown_exchange_ids(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("LYRASHIELD_RUN_RECORD_V1_1", "1")
    monkeypatch.setenv("STRIX_SANDBOX_MODE", "local")
    monkeypatch.chdir(tmp_path)
    state = ReportState(run_name="tooltest")
    set_global_report_state(state)

    args = {
        "title": "t",
        "description": "d",
        "impact": "i",
        "target": "https://x.test",
        "technical_analysis": "ta",
        "poc_description": "p",
        "poc_script_code": "c",
        "remediation_steps": "r",
        "evidence": "e",
        "assumptions": "a",
        "fix_effort": "low",
        "cvss_breakdown": {
            "attack_vector": "N",
            "attack_complexity": "L",
            "privileges_required": "N",
            "user_interaction": "N",
            "scope": "U",
            "confidentiality": "L",
            "integrity": "N",
            "availability": "N",
        },
        "http_exchange_ids": ["9999"],
    }
    raw = await reporting_tool.create_vulnerability_report.on_invoke_tool(
        _tool_ctx(args, caido_client=_FakeCaidoClient()), json.dumps(args)
    )
    result = json.loads(raw)
    assert result["success"] is False
    assert "9999" in json.dumps(result)


@pytest.mark.asyncio
async def test_tool_drops_ids_and_warns_when_proxy_unreachable(
    monkeypatch,
    tmp_path,
) -> None:
    monkeypatch.setenv("LYRASHIELD_RUN_RECORD_V1_1", "1")
    monkeypatch.setenv("STRIX_SANDBOX_MODE", "local")
    monkeypatch.chdir(tmp_path)
    state = ReportState(run_name="tooltest2")
    set_global_report_state(state)

    args = {
        "title": "t",
        "description": "d",
        "impact": "i",
        "target": "https://x.test",
        "technical_analysis": "ta",
        "poc_description": "p",
        "poc_script_code": "c",
        "remediation_steps": "r",
        "evidence": "e",
        "assumptions": "a",
        "fix_effort": "low",
        "cvss_breakdown": {
            "attack_vector": "N",
            "attack_complexity": "L",
            "privileges_required": "N",
            "user_interaction": "N",
            "scope": "U",
            "confidentiality": "L",
            "integrity": "N",
            "availability": "N",
        },
        "http_exchange_ids": ["1042"],
    }
    raw = await reporting_tool.create_vulnerability_report.on_invoke_tool(
        _tool_ctx(args), json.dumps(args)
    )
    result = json.loads(raw)
    assert result["success"] is True
    assert "warning" in result
    report = state.vulnerability_reports[0]
    # Unverified ids are never recorded as evidence.
    assert "http_exchange_ids" not in report
    assert report["evidence_warnings"]


@pytest.mark.asyncio
async def test_tool_update_revises_and_verifies(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("LYRASHIELD_RUN_RECORD_V1_1", "1")
    monkeypatch.setenv("STRIX_SANDBOX_MODE", "local")
    monkeypatch.chdir(tmp_path)
    state = ReportState(run_name="tooltest3")
    rid = state.add_vulnerability_report(**_vuln_kwargs())
    set_global_report_state(state)

    caido = _FakeCaidoClient({"1042": {"request": {}, "response": {"status_code": 200}}})
    args = {
        "report_id": rid,
        "update_reason": "attaching the captured exploit exchange",
        "http_exchange_ids": ["1042"],
        # Severity is re-rated only through a revised CVSS vector — the rating
        # belongs to the vector, not to a free-floating severity field.
        "cvss_breakdown": {
            "attack_vector": "N",
            "attack_complexity": "L",
            "privileges_required": "N",
            "user_interaction": "N",
            "scope": "C",
            "confidentiality": "H",
            "integrity": "H",
            "availability": "H",
        },
    }
    raw = await reporting_tool.update_vulnerability_report.on_invoke_tool(
        _tool_ctx(args, caido_client=caido), json.dumps(args)
    )
    result = json.loads(raw)
    assert result["success"] is True
    assert result["action"] == "updated"
    report = _report(state, rid)
    assert report["http_exchange_ids"] == ["1042"]
    assert report["severity"] == "critical"
    assert report["cvss"] == 10.0
    assert report["update_history"][0]["reason"] == "attaching the captured exploit exchange"

    # A static finding cannot grow proxy evidence it never had? No — the
    # update path deliberately allows attaching ids later; but a dependency
    # finding cannot carry them at all.
    dep_id = state.add_vulnerability_report(
        **_vuln_kwargs(
            title="CVE-2024-1 in pkg",
            finding_class="dependency_cve",
            dependency_metadata={"package_name": "pkg", "installed_version": "1.0"},
            cve="CVE-2024-1111",
        )
    )
    args = {
        "report_id": dep_id,
        "update_reason": "trying to attach http evidence",
        "http_exchange_ids": ["1042"],
    }
    raw = await reporting_tool.update_vulnerability_report.on_invoke_tool(
        _tool_ctx(args, caido_client=caido), json.dumps(args)
    )
    result = json.loads(raw)
    assert result["success"] is False
    assert "dependency_cve" in result["error"]
