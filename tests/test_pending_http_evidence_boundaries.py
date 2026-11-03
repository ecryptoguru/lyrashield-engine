"""Unavailable evidence, serialized limits and non-cooperative deadlines."""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from lyrashield.artifacts import evidence
from lyrashield.lifecycle.finalize import FinalizeServices, cleanup_scan_resources
from tests.test_pending_http_evidence import Client, exchange, file_claim
from tests.test_pending_http_evidence import pending_state as pending_state  # noqa: PLC0414


@pytest.mark.parametrize("prior", [False, True])
@pytest.mark.parametrize(
    "negative",
    ["outcome_missing", "outcome_capacity", "doc_missing", "doc_capacity", "doc_truncated"],
)
async def test_fresh_negative_capture_requires_independent_prior_proof(
    pending_state, prior, negative
):
    file_claim(pending_state, ["17"])
    if prior:
        await pending_state.reconcile_http_exchange_evidence(Client({"17": exchange()}))

    async def contradictory(client, directory, **kwargs):
        outcome = await evidence.export_http_exchange_evidence(client, directory, **kwargs)
        if negative.startswith("outcome"):
            key = (
                "missing_request_ids"
                if negative.endswith("missing")
                else "capacity_omitted_request_ids"
            )
            outcome[key] = ["17"]
        else:
            path = directory / "http_exchanges.json"
            doc = json.loads(path.read_text())
            if negative.endswith("truncated"):
                doc["truncated"] = {"omitted_request_ids": ["17"]}
            else:
                key = (
                    "missing_request_ids"
                    if negative.endswith("missing")
                    else "capacity_omitted_request_ids"
                )
                doc[key] = ["17"]
            payload = json.dumps(doc).encode()
            path.write_bytes(payload)
            outcome["sha256"] = hashlib.sha256(payload).hexdigest()
        return outcome

    outcome = await pending_state.reconcile_http_exchange_evidence(
        Client({"17": exchange()}),
        exporter=contradictory,
    )
    finding = pending_state.vulnerability_reports[0]
    if prior:
        assert outcome["status"] == "exported"
        assert outcome["reused_durable_exchanges"] == 1
        assert finding["http_exchange_ids"] == ["17"]
        assert finding["pending_http_exchange_ids"] == []
    else:
        assert outcome["status"] == "failed"
        assert not finding.get("http_exchange_ids")
        assert finding["pending_http_exchange_ids"] == ["17"]
        assert outcome["missing_request_ids"] == ["17"]


def test_byte_reduction_cannot_grow_valid_omissions_beyond_the_reader_limit():
    entries = []
    for number in range(40):
        capture = exchange()
        capture.response.raw = (
            "HTTP/1.1 200 OK\r\n" + "".join(f"X-{i}: {'x' * 502}\r\n" for i in range(64)) + "\r\n"
        ).encode()
        entries.append(evidence._export_one_exchange(str(number), capture))
    doc = {"exchanges": entries, "missing_request_ids": [str(i) for i in range(1000, 1500)]}
    payload = evidence.encode_http_exchange_document(doc)
    assert payload is None


@pytest.mark.parametrize("cancel_outer", [False, True])
async def test_noncooperative_export_cannot_delay_teardown_or_promote_late_results(
    pending_state, monkeypatch, cancel_outer
):
    file_claim(pending_state, ["17"])
    monkeypatch.setattr(evidence, "HTTP_EVIDENCE_EXPORT_TIMEOUT_SECONDS", 0.01)
    started, finished = asyncio.Event(), asyncio.Event()
    stage_paths = []

    async def late(client, directory, **kwargs):
        stage_paths.append(directory)
        started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            await asyncio.sleep(0.4)
            try:
                return await evidence.export_http_exchange_evidence(client, directory, **kwargs)
            finally:
                finished.set()

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
                export_http_exchange_evidence=late,
                set_active_hooks=lambda _hooks: None,
                configure_spill_writer=lambda _writer: None,
                cleanup_sandbox=teardown,
            ),
        )
    )
    await started.wait()
    start = time.monotonic()
    if cancel_outer:
        task.cancel()
    try:
        if cancel_outer:
            with pytest.raises(asyncio.CancelledError):
                await task
        else:
            await task
        assert time.monotonic() - start < 0.25
        assert teardown.await_count == 1
        assert not finished.is_set()
        assert stage_paths[0].is_dir()
        outcome = pending_state.run_record["evidence_export"]
        assert outcome["status"] == "failed"
        assert outcome["reason"] == ("export_cancelled" if cancel_outer else "export_timeout")
        assert not pending_state.vulnerability_reports[0].get("http_exchange_ids")
        path = pending_state.get_run_dir() / "http_exchanges.json"
        durable = path.read_bytes()
    finally:
        await asyncio.wait_for(finished.wait(), timeout=1)
        await asyncio.sleep(0)
    assert not stage_paths[0].exists()
    assert path.read_bytes() == durable
    assert not pending_state.vulnerability_reports[0].get("http_exchange_ids")
