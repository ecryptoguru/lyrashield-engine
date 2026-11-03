"""Schema 1.2 correlation claims require durable, revision-bound export."""

from __future__ import annotations

import asyncio
import hashlib
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from agents.usage import Usage

from lyrashield.artifacts import evidence, writer
from lyrashield.artifacts import state as state_module
from lyrashield.artifacts.dedupe import _prepare_report_for_comparison
from lyrashield.artifacts.finite_budget import GUARD
from lyrashield.artifacts.state import ReportState, set_global_report_state
from lyrashield.artifacts.state_findings import sanitize_finding
from lyrashield.artifacts.writer import read_run_record, snapshot_revision_artifacts
from lyrashield.lifecycle.finalize import FinalizeServices, cleanup_scan_resources
from lyrashield.tools.proxy import tools
from lyrashield.tools.reporting.tool import _verify_http_exchange_ids


@pytest.fixture
def pending_state(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("STRIX_SANDBOX_MODE", "local")
    monkeypatch.setenv("LYRASHIELD_RUN_RECORD_V1_1", "1")
    monkeypatch.setenv("LYRASHIELD_PENDING_HTTP_EVIDENCE", "1")
    state = ReportState(run_name="pending-http")
    set_global_report_state(state)
    yield state
    set_global_report_state(None)


def file_claim(state, ids=None):
    return state.add_vulnerability_report(
        title="Reflected input",
        description="HTML injection",
        severity="high",
        target="https://example.test",
        evidence="Observed reflected input",
        http_exchange_ids=ids or ["17", "18"],
    )


def exchange(host="example.test"):
    return SimpleNamespace(
        request=SimpleNamespace(
            host=host, raw=b"GET / HTTP/1.1\r\n\r\n", method="GET", port=443, is_tls=True, path="/"
        ),
        response=SimpleNamespace(raw=b"HTTP/1.1 200 OK\r\n\r\n", status_code=200),
    )


class Client:
    def __init__(self, entries):
        self.request = self
        self.entries = entries

    async def get(self, request_id, _opts=None):
        entry = self.entries.get(request_id)
        if isinstance(entry, Exception):
            raise entry
        return entry


def test_new_run_requires_both_flags(monkeypatch):
    monkeypatch.delenv("LYRASHIELD_PENDING_HTTP_EVIDENCE", raising=False)
    monkeypatch.setenv("LYRASHIELD_RUN_RECORD_V1_1", "1")
    assert evidence.run_record_schema_version() == "1.1"
    monkeypatch.setenv("LYRASHIELD_PENDING_HTTP_EVIDENCE", "1")
    assert evidence.run_record_schema_version() == "1.2"
    monkeypatch.delenv("LYRASHIELD_RUN_RECORD_V1_1")
    assert evidence.run_record_schema_version() == "1.0"


def test_claims_pending_without_verified_evidence(pending_state):
    rid = file_claim(pending_state)
    assert pending_state.run_record["schema_version"] == "1.2"
    report = pending_state.get_existing_vulnerabilities()[0]
    assert report["id"] == rid
    assert report["pending_http_exchange_ids"] == ["17", "18"]
    assert not report.get("http_exchange_ids")
    assert report["verification_state"] == "unverified"
    assert report["evidence_contract_version"] == "1.2"


@pytest.mark.parametrize("lookup", [None, set(), {"17"}, TimeoutError("unavailable")])
async def test_lookup_never_promotes_or_discards_claims(pending_state, monkeypatch, lookup):
    assert pending_state.run_record["schema_version"] == "1.2"

    async def existing(*_args):
        if isinstance(lookup, Exception):
            raise lookup
        return lookup, None

    monkeypatch.setattr(tools, "existing_request_ids", existing)
    ids, errors, warning = await _verify_http_exchange_ids(SimpleNamespace(), ["17"])
    assert ids == ["17"] and errors == []
    assert "pending" in warning.lower()


async def test_partial_export_then_later_reconciliation(pending_state):
    file_claim(pending_state)
    outcome = await pending_state.reconcile_http_exchange_evidence(
        Client({"17": exchange(), "18": TimeoutError("timeout")})
    )
    assert outcome["status"] == "partial"
    report = pending_state.vulnerability_reports[0]
    assert report["http_exchange_ids"] == ["17"]
    assert report["pending_http_exchange_ids"] == ["18"]
    assert report["verification_state"] == "unverified"
    evidence.verify_result_manifest(
        pending_state.get_run_dir(), pending_state.run_record["result_manifest"]
    )
    outcome = await pending_state.reconcile_http_exchange_evidence(
        Client({"17": exchange(), "18": exchange()})
    )
    assert outcome["status"] == "exported"
    assert pending_state.vulnerability_reports[0]["http_exchange_ids"] == ["17", "18"]
    assert pending_state.vulnerability_reports[0]["pending_http_exchange_ids"] == []
    artifact = json.loads((pending_state.get_run_dir() / "http_exchanges.json").read_text())
    binding = artifact["binding"]
    assert (
        binding["report_artifacts_revision"]
        == pending_state.run_record["report_artifacts_revision"]
    )
    assert binding["finding_revisions"] == {report["id"]: 0}


async def test_foreign_host_remains_pending(pending_state):
    file_claim(pending_state, ["17"])
    outcome = await pending_state.reconcile_http_exchange_evidence(
        Client({"17": exchange("foreign.test")})
    )
    assert outcome["status"] == "failed"
    assert pending_state.vulnerability_reports[0]["pending_http_exchange_ids"] == ["17"]
    assert not pending_state.vulnerability_reports[0].get("http_exchange_ids")


def test_pending_bounds_and_old_schema_projection():
    for ids in (["x"], ["\uff19"], ["1" * 129], [str(i) for i in range(11)]):
        assert evidence.normalize_pending_http_exchange_ids(ids)[1]
    report = {"id": "vuln-0001", "pending_http_exchange_ids": ["17", "17"]}
    assert sanitize_finding(report, include_internal_paths=False, schema_version="1.2")[
        "pending_http_exchange_ids"
    ] == ["17"]
    for version in ("1.0", "1.1"):
        assert "pending_http_exchange_ids" not in sanitize_finding(
            report, include_internal_paths=False, schema_version=version
        )


async def test_pending_survives_resume_with_writer_disabled(pending_state, monkeypatch):
    file_claim(pending_state)
    assert pending_state.save_run_data()
    monkeypatch.delenv("LYRASHIELD_PENDING_HTTP_EVIDENCE")
    monkeypatch.delenv("LYRASHIELD_RUN_RECORD_V1_1")
    resumed = ReportState(run_name=pending_state.run_name)
    resumed.hydrate_from_run_dir()
    assert resumed.run_record["schema_version"] == "1.2"
    assert resumed.get_existing_vulnerabilities()[0]["pending_http_exchange_ids"] == ["17", "18"]


@pytest.mark.parametrize(
    "field",
    [
        "run_id",
        "run_name",
        "report_artifacts_revision",
        "finding_revisions",
        "findings",
        "sha256",
        "boolean_revision",
    ],
)
async def test_forged_export_binding_never_promotes(pending_state, field):
    file_claim(pending_state, ["17"])
    assert pending_state.save_run_data()
    before = {
        path.name: path.read_bytes()
        for path in pending_state.get_run_dir().iterdir()
        if path.is_file()
    }

    async def forged(client, directory, **kwargs):
        outcome = await evidence.export_http_exchange_evidence(client, directory, **kwargs)
        path = directory / "http_exchanges.json"
        doc = json.loads(path.read_text())
        if field == "sha256":
            outcome["sha256"] = "f" * 64
        else:
            if field == "boolean_revision":
                doc["binding"]["report_artifacts_revision"] = True
            else:
                doc["binding"][field] = (
                    {} if field in {"findings", "finding_revisions"} else "foreign"
                )
            payload = json.dumps(doc).encode()
            path.write_bytes(payload)
            outcome["sha256"] = hashlib.sha256(payload).hexdigest()
        return outcome

    with pytest.raises((RuntimeError, TypeError), match="HTTP export"):
        await pending_state.reconcile_http_exchange_evidence(
            Client({"17": exchange()}), exporter=forged
        )
    assert not pending_state.vulnerability_reports[0].get("http_exchange_ids")
    assert before == {
        path.name: path.read_bytes()
        for path in pending_state.get_run_dir().iterdir()
        if path.is_file()
    }


async def test_receipt_failure_restores_claims_and_all_artifacts(pending_state, monkeypatch):
    file_claim(pending_state, ["17"])
    assert pending_state.save_run_data()
    before = snapshot_revision_artifacts(pending_state.get_run_dir())
    revision = pending_state.run_record["report_artifacts_revision"]

    def fail_receipt(*_args, **_kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(state_module, "write_run_record", fail_receipt)
    with pytest.raises(RuntimeError, match="receipt"):
        await pending_state.reconcile_http_exchange_evidence(Client({"17": exchange()}))
    assert pending_state.vulnerability_reports[0]["pending_http_exchange_ids"] == ["17"]
    assert not pending_state.vulnerability_reports[0].get("http_exchange_ids")
    assert pending_state.run_record["report_artifacts_revision"] == revision
    assert snapshot_revision_artifacts(pending_state.get_run_dir()) == before


async def test_updates_replace_claims_and_export_binds_final_finding_revision(pending_state):
    rid = file_claim(pending_state, ["17"])
    pending_state.update_vulnerability_report(
        rid, {"http_exchange_ids": ["18"]}, update_reason="New control"
    )
    assert pending_state.vulnerability_reports[0]["pending_http_exchange_ids"] == ["18"]
    await pending_state.reconcile_http_exchange_evidence(Client({"18": exchange()}))
    doc = json.loads((pending_state.get_run_dir() / "http_exchanges.json").read_text())
    assert doc["binding"]["finding_revisions"] == {rid: 1}
    assert pending_state.vulnerability_reports[0]["http_exchange_ids"] == ["18"]


@pytest.mark.parametrize("version", ["1.0", "1.1"])
def test_resume_never_upgrades_old_contract(tmp_path, monkeypatch, version):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("LYRASHIELD_PENDING_HTTP_EVIDENCE", raising=False)
    monkeypatch.setenv("STRIX_SANDBOX_MODE", "local")
    monkeypatch.setenv("LYRASHIELD_RUN_RECORD_V1_1", "1" if version == "1.1" else "0")
    old = ReportState(run_name="old-contract")
    file_claim(old, ["17"])
    assert old.save_run_data()
    monkeypatch.setenv("LYRASHIELD_PENDING_HTTP_EVIDENCE", "1")
    monkeypatch.setenv("LYRASHIELD_RUN_RECORD_V1_1", "1")
    resumed = ReportState(run_name=old.run_name)
    resumed.hydrate_from_run_dir()
    assert resumed.run_record["schema_version"] == version
    assert "pending_http_exchange_ids" not in resumed.get_existing_vulnerabilities()[0]


def test_pending_claims_never_change_dedupe_identity():
    finding = {"title": "Reflected input", "target": "https://example.test", "endpoint": "/"}
    assert _prepare_report_for_comparison(finding) == _prepare_report_for_comparison(
        {
            **finding,
            "pending_http_exchange_ids": ["17"],
            "http_exchange_ids": ["18"],
        }
    )


async def test_reconciliation_precedes_sandbox_teardown(pending_state):
    file_claim(pending_state, ["17"])
    events = []

    async def export(*args, **kwargs):
        events.append("export")
        return await evidence.export_http_exchange_evidence(*args, **kwargs)

    async def cleanup(_scan_id):
        assert pending_state.vulnerability_reports[0]["http_exchange_ids"] == ["17"]
        evidence.verify_result_manifest(
            pending_state.get_run_dir(), pending_state.run_record["result_manifest"]
        )
        events.append("teardown")
        return "removed"

    await cleanup_scan_resources(
        scan_id=pending_state.run_id,
        sessions_to_close=[],
        coordinator=SimpleNamespace(maybe_snapshot=AsyncMock()),
        artifact_state=pending_state,
        bundle={"caido_client": Client({"17": exchange()})},
        cleanup_on_exit=True,
        paths=SimpleNamespace(teardown_logging=lambda: None),
        services=FinalizeServices(
            get_global_report_state=lambda: pending_state,
            record_supports_evidence=evidence.record_supports_evidence_v1_1,
            export_http_exchange_evidence=export,
            set_active_hooks=lambda _hooks: None,
            configure_spill_writer=lambda _writer: None,
            cleanup_sandbox=cleanup,
        ),
    )
    assert events == ["export", "teardown"]


async def test_real_lookup_timeout_preserves_claims(pending_state, monkeypatch):
    file_claim(pending_state, ["17"])
    monkeypatch.setattr(evidence, "HTTP_EVIDENCE_LOOKUP_TIMEOUT_SECONDS", 0.001)

    class SlowClient:
        request = None

        def __init__(self):
            self.request = self

        async def get(self, *_args):
            await asyncio.sleep(1)
            return exchange()

    outcome = await pending_state.reconcile_http_exchange_evidence(SlowClient())
    assert outcome["status"] == "failed"
    assert outcome["missing_request_ids"] == ["17"]
    assert pending_state.vulnerability_reports[0]["pending_http_exchange_ids"] == ["17"]
    assert not pending_state.vulnerability_reports[0].get("http_exchange_ids")


async def test_missing_proxy_preserves_claims_and_explicit_outcome(pending_state):
    file_claim(pending_state, ["17"])
    outcome = await pending_state.reconcile_http_exchange_evidence(None)
    assert outcome["status"] == "failed"
    assert outcome["missing_request_ids"] == ["17"]
    assert pending_state.vulnerability_reports[0]["pending_http_exchange_ids"] == ["17"]
    assert (
        "HTTP Exchange Evidence"
        not in (pending_state.get_run_dir() / "vulnerabilities" / "vuln-0001.md").read_text()
    )


async def test_export_cap_never_promotes_omitted_ids(pending_state, monkeypatch):
    file_claim(pending_state)
    monkeypatch.setattr(evidence, "MAX_EXPORT_EXCHANGES", 1)
    outcome = await pending_state.reconcile_http_exchange_evidence(
        Client({"17": exchange(), "18": exchange()})
    )
    assert outcome["status"] == "partial"
    assert pending_state.vulnerability_reports[0]["http_exchange_ids"] == ["17"]
    assert pending_state.vulnerability_reports[0]["pending_http_exchange_ids"] == ["18"]


@pytest.mark.parametrize(("verified_count", "pending_count"), [(10, 1), (1, 10)])
async def test_independent_arrays_keep_verified_first_and_overflow_pending(
    pending_state, verified_count, pending_count
):
    rid = file_claim(pending_state, ["17"])
    report = pending_state.vulnerability_reports[0]
    verified = [str(i) for i in range(1, verified_count + 1)]
    pending = [str(i) for i in range(21, 21 + pending_count)]
    report["http_exchange_ids"] = verified
    report["pending_http_exchange_ids"] = pending
    assert pending_state.save_run_data()
    outcome = await pending_state.reconcile_http_exchange_evidence(
        Client({value: exchange() for value in verified + pending})
    )
    selected = (verified + pending)[:10]
    remaining = (verified + pending)[10:]
    assert outcome["status"] == "partial"
    assert outcome["capacity_omitted_request_ids"] == remaining
    report = pending_state.vulnerability_reports[0]
    assert report["http_exchange_ids"] == selected
    assert report["pending_http_exchange_ids"] == remaining
    artifact = json.loads((pending_state.get_run_dir() / "http_exchanges.json").read_text())
    assert artifact["binding"]["findings"] == {rid: selected}
    resumed = ReportState(run_name=pending_state.run_name)
    resumed.hydrate_from_run_dir()
    assert resumed.get_existing_vulnerabilities()[0]["http_exchange_ids"] == selected
    assert resumed.get_existing_vulnerabilities()[0]["pending_http_exchange_ids"] == remaining


async def test_later_outage_preserves_prior_durable_verified_capture(pending_state):
    file_claim(pending_state)
    await pending_state.reconcile_http_exchange_evidence(Client({"17": exchange()}))
    outcome = await pending_state.reconcile_http_exchange_evidence(None)
    assert outcome["status"] == "partial"
    assert outcome["reused_durable_exchanges"] == 1
    assert pending_state.vulnerability_reports[0]["http_exchange_ids"] == ["17"]
    assert pending_state.vulnerability_reports[0]["pending_http_exchange_ids"] == ["18"]
    artifact = json.loads((pending_state.get_run_dir() / "http_exchanges.json").read_text())
    assert (
        artifact["binding"]["report_artifacts_revision"]
        == pending_state.run_record["report_artifacts_revision"]
    )
    evidence.verify_result_manifest(
        pending_state.get_run_dir(), pending_state.run_record["result_manifest"]
    )


async def test_reused_capture_is_removed_from_fresh_export_omissions(pending_state, monkeypatch):
    first = file_claim(pending_state, ["17", "19"])
    second = file_claim(pending_state, ["18"])
    await pending_state.reconcile_http_exchange_evidence(
        Client({"17": exchange(), "18": exchange()})
    )
    monkeypatch.setattr(evidence, "MAX_EXPORT_EXCHANGES", 2)
    outcome = await pending_state.reconcile_http_exchange_evidence(Client({"17": exchange()}))
    doc = json.loads((pending_state.get_run_dir() / "http_exchanges.json").read_text())
    exported = {entry["proxy_request_id"] for entry in doc["exchanges"]}
    omitted = set(doc.get("truncated", {}).get("omitted_request_ids", []))
    assert exported == {"17", "18"}
    assert not exported.intersection(omitted)
    assert not exported.intersection(doc.get("missing_request_ids", []))
    assert not exported.intersection(outcome.get("missing_request_ids", []))
    by_id = {finding["id"]: finding for finding in pending_state.get_existing_vulnerabilities()}
    assert by_id[first]["pending_http_exchange_ids"] == ["19"]
    assert by_id[second]["http_exchange_ids"] == ["18"]


async def test_pending_http_rollback_cannot_erase_interleaved_financial_settlement(
    pending_state, monkeypatch
):
    file_claim(pending_state, ["17"])
    owner = pending_state.enable_finite_budget(1)
    assert pending_state.save_run_data()
    revision = pending_state.run_record["report_artifacts_revision"]
    paid = owner.reserve(0.6)
    pending_state._adopt_financial_snapshot(owner.snapshot())
    interleaved = False

    def fail_after_known_settlement(*_args, **_kwargs):
        nonlocal interleaved
        if not interleaved:
            interleaved = True
            with monkeypatch.context() as patch:
                patch.setattr(pending_state, "save_run_data", lambda **_kw: False)
                pending_state.record_sdk_usage(
                    agent_id="root",
                    model="openai/gpt-6-luna",
                    usage=Usage(requests=1, input_tokens=7, output_tokens=2, total_tokens=9),
                    budget_attempt=paid,
                    budget_cost=0.17,
                )
            owner.reserve(0.6)
        raise OSError("report receipt projection failed")

    monkeypatch.setattr(state_module, "write_run_record", fail_after_known_settlement)
    with pytest.raises(RuntimeError, match="receipt"):
        await pending_state.reconcile_http_exchange_evidence(Client({"17": exchange()}))
    assert interleaved
    assert pending_state.vulnerability_reports[0]["pending_http_exchange_ids"] == ["17"]
    assert not pending_state.vulnerability_reports[0].get("http_exchange_ids")
    current = read_run_record(pending_state.get_run_dir())
    assert current["report_artifacts_revision"] == revision
    assert current["llm_usage"]["total_tokens"] == 9
    assert len(current[GUARD]["pending"]) == 1
    assert pending_state.run_record[GUARD] == current[GUARD]


@pytest.mark.parametrize("text_newline", ["\r\n", "\n"])
async def test_export_digest_matches_exact_bytes_with_platform_text_newlines(
    pending_state, monkeypatch, text_newline
):
    original = writer.tempfile.NamedTemporaryFile

    def platform_text_file(*args, **kwargs):
        if kwargs.get("mode") == "w":
            kwargs["newline"] = text_newline
        return original(*args, **kwargs)

    monkeypatch.setattr(writer.tempfile, "NamedTemporaryFile", platform_text_file)
    file_claim(pending_state, ["17"])
    captured = exchange()
    captured.request.path = "/café"
    outcome = await pending_state.reconcile_http_exchange_evidence(Client({"17": captured}))
    payload = (pending_state.get_run_dir() / evidence.HTTP_EXCHANGES_FILENAME).read_bytes()
    assert "café" in payload.decode("utf-8")
    assert outcome["sha256"] == hashlib.sha256(payload).hexdigest()
    assert b"\r\n" not in payload
    assert pending_state.vulnerability_reports[0]["http_exchange_ids"] == ["17"]
    assert not pending_state.vulnerability_reports[0].get("pending_http_exchange_ids")
    manifest = pending_state.run_record["result_manifest"]
    evidence.verify_result_manifest(pending_state.get_run_dir(), manifest)
