"""Failure and concurrency contracts for durable pending HTTP reconciliation."""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from lyrashield.artifacts import evidence
from lyrashield.artifacts.state import ReportState
from lyrashield.lifecycle.finalize import FinalizeServices, cleanup_scan_resources
from tests.test_pending_http_evidence import Client, exchange, file_claim
from tests.test_pending_http_evidence import pending_state as pending_state  # noqa: PLC0414


@pytest.mark.parametrize("damage", ["both", "findings", "http", "bytes"])
async def test_offline_reuse_requires_original_mandatory_manifest_entries(pending_state, damage):
    file_claim(pending_state, ["17"])
    await pending_state.reconcile_http_exchange_evidence(Client({"17": exchange()}))
    path = pending_state.get_run_dir() / "run.json"
    record = json.loads(path.read_text())
    entries = record["result_manifest"]["artifacts"]
    if damage in {"both", "findings"}:
        entries.pop("vulnerabilities.json")
    if damage in {"both", "http"}:
        entries.pop("http_exchanges.json")
    if damage == "bytes":
        entries["http_exchanges.json"].pop("bytes")
    path.write_text(json.dumps(record))
    resumed = ReportState(run_name=pending_state.run_name)
    if damage == "bytes":
        with pytest.raises(RuntimeError, match="manifest"):
            resumed.hydrate_from_run_dir()
        return
    resumed.hydrate_from_run_dir()
    outcome = await resumed.reconcile_http_exchange_evidence(None)
    assert outcome["status"] == "failed"
    assert not resumed.vulnerability_reports[0].get("http_exchange_ids")
    assert resumed.vulnerability_reports[0]["pending_http_exchange_ids"] == ["17"]


async def test_partial_capture_reuse_is_independent_of_claim_display_order(pending_state):
    file_claim(pending_state, ["17", "18"])
    await pending_state.reconcile_http_exchange_evidence(Client({"18": exchange()}))
    outcome = await pending_state.reconcile_http_exchange_evidence(None)
    assert outcome["status"] == "partial"
    assert outcome["reused_durable_exchanges"] == 1
    assert pending_state.vulnerability_reports[0]["http_exchange_ids"] == ["18"]
    assert pending_state.vulnerability_reports[0]["pending_http_exchange_ids"] == ["17"]


async def test_authored_update_demotes_stale_capture_and_persists_unavailability(pending_state):
    rid = file_claim(pending_state, ["17"])
    await pending_state.reconcile_http_exchange_evidence(Client({"17": exchange()}))
    pending_state.update_vulnerability_report(
        rid, {"title": "Revised title"}, update_reason="Clarify"
    )
    assert not pending_state.vulnerability_reports[0].get("http_exchange_ids")
    outcome = await pending_state.reconcile_http_exchange_evidence(None)
    assert outcome["status"] == "failed"
    stored = json.loads((pending_state.get_run_dir() / "vulnerabilities.json").read_text())[0]
    assert stored["pending_http_exchange_ids"] == ["17"]
    assert not stored.get("http_exchange_ids")
    assert (
        "http_evidence_unavailable"
        in pending_state.run_record["scan_quality"]["assessment_reasons"]
    )


async def test_all_unavailable_overflow_preserves_both_bounded_claim_arrays(pending_state):
    file_claim(pending_state, ["17"])
    finding = pending_state.vulnerability_reports[0]
    finding["http_exchange_ids"] = ["1"]
    finding["pending_http_exchange_ids"] = [str(i) for i in range(20, 30)]
    pending_state._report_artifacts_revision += 1
    assert pending_state.save_run_data()
    path = pending_state.get_run_dir() / "vulnerabilities.json"
    before = path.read_bytes()
    for _ in range(2):
        outcome = await pending_state.reconcile_http_exchange_evidence(Client({}))
        assert outcome["status"] == "failed"
        assert outcome["reason"] == "pending_capacity_exceeded"
        assert path.read_bytes() == before
        assert pending_state.run_record["evidence_export"]["status"] == "failed"
    resumed = ReportState(run_name=pending_state.run_name)
    resumed.hydrate_from_run_dir()
    finding = resumed.vulnerability_reports[0]
    assert finding["http_exchange_ids"] == ["1"]
    assert finding["pending_http_exchange_ids"] == [str(i) for i in range(20, 30)]


async def test_cross_finding_capacity_does_not_globally_exclude_captured_shared_id(pending_state):
    first = file_claim(pending_state, ["17"])
    pending_state.vulnerability_reports[0]["http_exchange_ids"] = [str(i) for i in range(1, 11)]
    pending_state.vulnerability_reports[0]["pending_http_exchange_ids"] = ["99"]
    second = file_claim(pending_state, ["99"])
    outcome = await pending_state.reconcile_http_exchange_evidence(
        Client({str(i): exchange() for i in range(1, 11)} | {"99": exchange()})
    )
    doc = json.loads((pending_state.get_run_dir() / "http_exchanges.json").read_text())
    assert "99" not in outcome.get("capacity_omitted_request_ids", [])
    assert "99" not in doc.get("capacity_omitted_request_ids", [])
    reports = {finding["id"]: finding for finding in pending_state.vulnerability_reports}
    assert reports[first]["pending_http_exchange_ids"] == ["99"]
    assert reports[second]["http_exchange_ids"] == ["99"]


@pytest.mark.parametrize("concurrent", ["success", "authored_update"])
async def test_slow_no_artifact_failure_cannot_overwrite_newer_revision(pending_state, concurrent):
    rid = file_claim(pending_state, ["17"])
    started, release = asyncio.Event(), asyncio.Event()

    async def delayed(*_args, **_kwargs):
        started.set()
        await release.wait()
        return {"status": "failed", "exchanges": 0}

    task = asyncio.create_task(
        pending_state.reconcile_http_exchange_evidence(None, exporter=delayed)
    )
    await started.wait()
    if concurrent == "success":
        await pending_state.reconcile_http_exchange_evidence(Client({"17": exchange()}))
    else:
        pending_state.update_vulnerability_report(
            rid, {"title": "Updated"}, update_reason="New data"
        )
    before = (pending_state.get_run_dir() / "run.json").read_bytes()
    release.set()
    with pytest.raises(RuntimeError, match="revision"):
        await task
    assert (pending_state.get_run_dir() / "run.json").read_bytes() == before


def test_repeated_pending_update_is_noop_and_empty_submission_clears(pending_state):
    rid = file_claim(pending_state, ["17"])
    for _ in range(3):
        result = pending_state.update_vulnerability_report(
            rid, {"http_exchange_ids": ["17"]}, update_reason="Retry"
        )
        assert result is None
    assert not pending_state.vulnerability_reports[0].get("update_history")
    pending_state.update_vulnerability_report(
        rid, {"http_exchange_ids": []}, update_reason="Detach"
    )
    assert pending_state.vulnerability_reports[0]["pending_http_exchange_ids"] == []
    assert len(pending_state.vulnerability_reports[0]["update_history"]) == 1


async def test_large_header_export_never_exceeds_serialized_byte_budget(pending_state):
    file_claim(pending_state, ["17"])
    capture = exchange()
    capture.response.raw = (
        "HTTP/1.1 200 OK\r\n" + "".join(f"X-{i}: {'a' * 502}\r\n" for i in range(4300)) + "\r\n"
    ).encode()
    outcome = await pending_state.reconcile_http_exchange_evidence(Client({"17": capture}))
    path = pending_state.get_run_dir() / "http_exchanges.json"
    assert path.stat().st_size <= evidence.MAX_EXPORT_TOTAL_BYTES
    assert outcome["status"] in {"exported", "partial"}


async def test_unrepresentable_export_is_failed_without_promotion(pending_state, monkeypatch):
    file_claim(pending_state, ["17"])
    monkeypatch.setattr(evidence, "MAX_EXPORT_TOTAL_BYTES", 64)
    outcome = await pending_state.reconcile_http_exchange_evidence(Client({"17": exchange()}))
    assert outcome["status"] == "failed"
    assert not pending_state.vulnerability_reports[0].get("http_exchange_ids")
    path = pending_state.get_run_dir() / "http_exchanges.json"
    assert not path.exists() or path.stat().st_size <= 64


async def test_legacy_success_cap_counts_captured_exchanges(pending_state, monkeypatch, tmp_path):
    monkeypatch.setattr(evidence, "MAX_EXPORT_EXCHANGES", 1)
    outcome = await evidence.export_http_exchange_evidence(
        Client({"18": exchange()}),
        tmp_path,
        run_record={"schema_version": "1.1"},
        findings=[{"id": "vuln-0001", "http_exchange_ids": ["17", "18"]}],
    )
    assert outcome["status"] == "partial"
    assert outcome["exchanges"] == 1
    assert pending_state.run_record["schema_version"] == "1.2"


async def test_cancelled_export_always_tears_down_once_and_propagates(pending_state):
    file_claim(pending_state, ["17"])
    started = asyncio.Event()

    async def exporting(*_args, **_kwargs):
        started.set()
        await asyncio.Event().wait()

    teardown, logging = AsyncMock(return_value="removed"), Mock()
    task = asyncio.create_task(
        cleanup_scan_resources(
            scan_id=pending_state.run_id,
            sessions_to_close=[],
            coordinator=SimpleNamespace(maybe_snapshot=AsyncMock()),
            artifact_state=pending_state,
            bundle={},
            cleanup_on_exit=True,
            paths=SimpleNamespace(teardown_logging=logging),
            services=FinalizeServices(
                get_global_report_state=lambda: pending_state,
                record_supports_evidence=evidence.record_supports_evidence_v1_1,
                export_http_exchange_evidence=exporting,
                set_active_hooks=lambda _hooks: None,
                configure_spill_writer=lambda _writer: None,
                cleanup_sandbox=teardown,
            ),
        )
    )
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert teardown.await_count == 1
    assert logging.call_count == 1


async def test_total_export_timeout_commits_only_unavailable_claims(pending_state, monkeypatch):
    file_claim(pending_state, ["17"])
    monkeypatch.setattr(evidence, "HTTP_EVIDENCE_EXPORT_TIMEOUT_SECONDS", 0.001)

    async def hanging(*_args, **_kwargs):
        await asyncio.Event().wait()

    outcome = await pending_state.reconcile_http_exchange_evidence(None, exporter=hanging)
    assert outcome["status"] == "failed"
    assert outcome["reason"] == "export_timeout"
    assert pending_state.vulnerability_reports[0]["pending_http_exchange_ids"] == ["17"]
    assert not pending_state.vulnerability_reports[0].get("http_exchange_ids")


async def test_finalizer_does_not_overwrite_newer_success_after_stale_export(pending_state):
    file_claim(pending_state, ["17"])
    started, release = asyncio.Event(), asyncio.Event()

    async def delayed(*_args, **_kwargs):
        started.set()
        await release.wait()
        return {"status": "failed", "exchanges": 0}

    teardown = AsyncMock(return_value="removed")
    task = asyncio.create_task(
        cleanup_scan_resources(
            scan_id=pending_state.run_id,
            sessions_to_close=[],
            coordinator=SimpleNamespace(maybe_snapshot=AsyncMock()),
            artifact_state=pending_state,
            bundle={},
            cleanup_on_exit=True,
            paths=SimpleNamespace(teardown_logging=lambda: None),
            services=FinalizeServices(
                get_global_report_state=lambda: pending_state,
                record_supports_evidence=evidence.record_supports_evidence_v1_1,
                export_http_exchange_evidence=delayed,
                set_active_hooks=lambda _hooks: None,
                configure_spill_writer=lambda _writer: None,
                cleanup_sandbox=teardown,
            ),
        )
    )
    await started.wait()
    await pending_state.reconcile_http_exchange_evidence(Client({"17": exchange()}))
    sha = pending_state.run_record["evidence_export"]["sha256"]
    release.set()
    await task
    assert pending_state.run_record["evidence_export"]["status"] == "exported"
    assert pending_state.run_record["evidence_export"]["sha256"] == sha
    assert teardown.await_count == 1


async def test_merged_export_respects_exact_final_size_and_digest(pending_state, monkeypatch):
    file_claim(pending_state, ["17", "18"])
    await pending_state.reconcile_http_exchange_evidence(Client({"17": exchange()}))
    monkeypatch.setattr(evidence, "MAX_EXPORT_TOTAL_BYTES", 2000)
    outcome = await pending_state.reconcile_http_exchange_evidence(Client({"18": exchange()}))
    path = pending_state.get_run_dir() / "http_exchanges.json"
    assert path.stat().st_size <= 2000
    manifest = pending_state.run_record["result_manifest"]["artifacts"]["http_exchanges.json"]
    assert outcome["sha256"] == manifest["sha256"]
    assert manifest["bytes"] == path.stat().st_size
    doc = json.loads(path.read_text())
    assert outcome["exchanges"] == len(doc["exchanges"])
    assert not set(outcome.get("missing_request_ids", [])).intersection(
        entry["proxy_request_id"] for entry in doc["exchanges"]
    )


async def test_explicit_failed_overflow_receipt_still_allows_sandbox_cleanup(pending_state):
    file_claim(pending_state, ["17"])
    finding = pending_state.vulnerability_reports[0]
    finding["http_exchange_ids"] = ["1"]
    finding["pending_http_exchange_ids"] = [str(i) for i in range(20, 30)]
    pending_state._report_artifacts_revision += 1
    assert pending_state.save_run_data()
    teardown = AsyncMock(return_value="removed")
    await cleanup_scan_resources(
        scan_id=pending_state.run_id,
        sessions_to_close=[],
        coordinator=SimpleNamespace(maybe_snapshot=AsyncMock()),
        artifact_state=pending_state,
        bundle={"caido_client": Client({})},
        cleanup_on_exit=True,
        paths=SimpleNamespace(teardown_logging=lambda: None),
        services=FinalizeServices(
            get_global_report_state=lambda: pending_state,
            record_supports_evidence=evidence.record_supports_evidence_v1_1,
            export_http_exchange_evidence=evidence.export_http_exchange_evidence,
            set_active_hooks=lambda _hooks: None,
            configure_spill_writer=lambda _writer: None,
            cleanup_sandbox=teardown,
        ),
    )
    assert teardown.await_count == 1
    assert pending_state.run_record["evidence_export"]["status"] == "failed"
    assert pending_state.run_record["evidence_export"]["reason"] == "pending_capacity_exceeded"
    assert (
        "http_evidence_unavailable"
        in pending_state.run_record["scan_quality"]["assessment_reasons"]
    )


def test_negative_availability_lists_are_validated_without_truncating():
    assert evidence.valid_http_omission_ids([str(i) for i in range(500)])
    for raw in (
        [str(i) for i in range(501)],
        ["1"] * 500 + ["foreign"],
        ["\uff11"],
        [" 17"],
        ["1" * 129],
    ):
        assert not evidence.valid_http_omission_ids(raw)


async def test_source_run_name_cannot_be_reendorsed_under_another_runtime_identity(pending_state):
    file_claim(pending_state, ["17"])
    await pending_state.reconcile_http_exchange_evidence(Client({"17": exchange()}))
    pending_state.run_record["run_name"] = "foreign-run"
    before = (pending_state.get_run_dir() / "run.json").read_bytes()
    with pytest.raises(RuntimeError, match="source run identity"):
        await pending_state.reconcile_http_exchange_evidence(None)
    assert (pending_state.get_run_dir() / "run.json").read_bytes() == before


async def test_cancellation_after_staged_write_never_promotes_and_still_cleans_up(pending_state):
    file_claim(pending_state, ["17"])
    staged = asyncio.Event()

    async def staged_then_waiting(client, directory, **kwargs):
        await evidence.export_http_exchange_evidence(client, directory, **kwargs)
        staged.set()
        await asyncio.Event().wait()

    teardown = AsyncMock(return_value="removed")
    task = asyncio.create_task(
        cleanup_scan_resources(
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
                export_http_exchange_evidence=staged_then_waiting,
                set_active_hooks=lambda _hooks: None,
                configure_spill_writer=lambda _writer: None,
                cleanup_sandbox=teardown,
            ),
        )
    )
    await staged.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert teardown.await_count == 1
    assert pending_state.run_record["evidence_export"]["status"] == "failed"
    assert pending_state.run_record["evidence_export"]["reason"] == "export_cancelled"
    assert not pending_state.vulnerability_reports[0].get("http_exchange_ids")


async def test_repeated_cancellation_during_cleanup_waits_for_the_one_attempt(pending_state):
    file_claim(pending_state, ["17"])
    exporting, cleaning, release = asyncio.Event(), asyncio.Event(), asyncio.Event()

    async def export(*_args, **_kwargs):
        exporting.set()
        await asyncio.Event().wait()

    async def cleanup(_scan_id):
        cleaning.set()
        await release.wait()
        return "removed"

    teardown = AsyncMock(side_effect=cleanup)
    logging = Mock()
    task = asyncio.create_task(
        cleanup_scan_resources(
            scan_id=pending_state.run_id,
            sessions_to_close=[],
            coordinator=SimpleNamespace(maybe_snapshot=AsyncMock()),
            artifact_state=pending_state,
            bundle={},
            cleanup_on_exit=True,
            paths=SimpleNamespace(teardown_logging=logging),
            services=FinalizeServices(
                get_global_report_state=lambda: pending_state,
                record_supports_evidence=evidence.record_supports_evidence_v1_1,
                export_http_exchange_evidence=export,
                set_active_hooks=lambda _hooks: None,
                configure_spill_writer=lambda _writer: None,
                cleanup_sandbox=teardown,
            ),
        )
    )
    await exporting.wait()
    task.cancel()
    await cleaning.wait()
    task.cancel()
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert teardown.await_count == 1
    assert logging.call_count == 1
    assert pending_state.run_record["cleanup"]["sandbox_removed"] is True


async def test_too_many_unavailable_ids_fail_without_truncating_claims_or_emitting_invalid_lists(
    pending_state,
):
    expected = []
    for batch in range(51):
        ids = [str(batch * 10 + offset) for offset in range(10)]
        file_claim(pending_state, ids)
        expected.extend(ids)
    outcome = await pending_state.reconcile_http_exchange_evidence(None)
    assert outcome["status"] == "failed"
    assert outcome["reason"] == "export_size_exceeded"
    assert evidence.valid_http_omission_ids(outcome.get("missing_request_ids", []))
    assert not (pending_state.get_run_dir() / "http_exchanges.json").exists()
    assert expected == [
        request_id
        for finding in pending_state.get_existing_vulnerabilities()
        for request_id in finding["pending_http_exchange_ids"]
    ]


async def test_unnamed_run_resumes_by_its_generated_id_without_losing_durable_capture(
    pending_state,
):
    assert pending_state.run_record["schema_version"] == "1.2"
    state = ReportState()
    file_claim(state, ["17"])
    await state.reconcile_http_exchange_evidence(Client({"17": exchange()}))
    resumed = ReportState(run_name=state.run_id)
    resumed.hydrate_from_run_dir()
    outcome = await resumed.reconcile_http_exchange_evidence(None)
    assert outcome["status"] == "exported"
    assert outcome["reused_durable_exchanges"] == 1
    assert resumed.vulnerability_reports[0]["http_exchange_ids"] == ["17"]
