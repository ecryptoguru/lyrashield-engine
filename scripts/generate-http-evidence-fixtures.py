#!/usr/bin/env python3
"""Generate synthetic HTTP evidence bundles for independent consumer qualification.

Run from the repository root with PYTHONPATH=. and the engine environment.
No provider, proxy, target or deployment calls are made. The output must be a
new directory under an existing parent; existing paths are never replaced.
"""

from __future__ import annotations

import argparse
import asyncio
import functools
import hashlib
import json
import os
import tempfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any


os.environ["LITELLM_LOCAL_MODEL_COST_MAP"] = "True"
os.environ["STRIX_TELEMETRY"] = "0"
os.environ["LYRASHIELD_TELEMETRY"] = "0"

from lyrashield.artifacts import evidence
from lyrashield.artifacts.state import ReportState


STANDARD_CASES = (
    "reverse-reuse",
    "shared-capacity",
    "overflow-failed",
    "header-bound",
    "max-bytes",
)
NEGATIVE_CASES = (
    "outcome-missing",
    "outcome-capacity",
    "doc-missing",
    "doc-capacity",
    "doc-truncated",
    "negative-with-prior",
    "deadline-late",
    "omission-limit",
)


class SyntheticClient:
    def __init__(self, entries: dict[str, Any]) -> None:
        self.request = self
        self.entries = entries

    async def get(self, request_id: str, _options: Any = None) -> Any:
        return self.entries.get(request_id)


def _exchange(*, headers: int = 0) -> SimpleNamespace:
    response = "HTTP/1.1 200 OK\r\n"
    response += "".join(f"X-{number}: {'x' * 502}\r\n" for number in range(headers))
    return SimpleNamespace(
        request=SimpleNamespace(
            host="example.test",
            raw=b"GET / HTTP/1.1\r\n\r\n",
            method="GET",
            path="/",
            port=443,
            is_tls=True,
        ),
        response=SimpleNamespace(raw=(response + "\r\n").encode(), status_code=200),
    )


def _claim(state: ReportState, ids: list[str]) -> str:
    return state.add_vulnerability_report(
        title="Synthetic reflected input",
        description="Synthetic captured response",
        severity="high",
        target="https://example.test",
        evidence="Synthetic fixture only",
        http_exchange_ids=ids,
    )


async def _negative_export(
    client: Any,
    directory: Path,
    *,
    negative: str,
    **kwargs: Any,
) -> dict[str, Any]:
    outcome = await evidence.export_http_exchange_evidence(client, directory, **kwargs)
    field = (
        "missing_request_ids" if negative.endswith("missing") else "capacity_omitted_request_ids"
    )
    if negative.startswith("outcome"):
        outcome[field] = ["17"]
    else:
        path = directory / evidence.HTTP_EXCHANGES_FILENAME
        document = json.loads(path.read_text(encoding="utf-8"))
        if negative.endswith("truncated"):
            document["truncated"] = {"omitted_request_ids": ["17"]}
        else:
            document[field] = ["17"]
        payload = json.dumps(document).encode("utf-8")
        path.write_bytes(payload)
        outcome["sha256"] = hashlib.sha256(payload).hexdigest()
    return outcome


async def _run_case(state: ReportState, case: str) -> dict[str, Any]:
    if case == "reverse-reuse":
        _claim(state, ["17", "18"])
        await state.reconcile_http_exchange_evidence(SyntheticClient({"18": _exchange()}))
        return await state.reconcile_http_exchange_evidence(None)
    if case in {"shared-capacity", "overflow-failed"}:
        _claim(state, ["17"])
        finding = state.vulnerability_reports[0]
        finding["http_exchange_ids"] = (
            [str(number) for number in range(1, 11)] if case == "shared-capacity" else ["1"]
        )
        finding["pending_http_exchange_ids"] = (
            ["99"] if case == "shared-capacity" else [str(number) for number in range(20, 30)]
        )
        if case == "shared-capacity":
            _claim(state, ["99"])
            entries = {str(number): _exchange() for number in range(1, 11)} | {"99": _exchange()}
        else:
            state._report_artifacts_revision += 1
            state.save_run_data()
            entries = {}
        return await state.reconcile_http_exchange_evidence(SyntheticClient(entries))
    if case in {"max-bytes", "omission-limit"}:
        count = 64 if case == "max-bytes" else 560
        entries = {}
        for start in range(1, count + 1, 10):
            ids = [str(number) for number in range(start, min(start + 10, count + 1))]
            _claim(state, ids)
            entries.update(
                {
                    request_id: _exchange(headers=64)
                    for request_id in ids
                    if int(request_id) <= (64 if case == "max-bytes" else 40)
                }
            )
        return await state.reconcile_http_exchange_evidence(SyntheticClient(entries))
    _claim(state, ["17"])
    if case == "header-bound":
        return await state.reconcile_http_exchange_evidence(
            SyntheticClient({"17": _exchange(headers=4300)})
        )
    if case == "deadline-late":
        settled = asyncio.Event()

        async def late(client: Any, directory: Path, **kwargs: Any) -> dict[str, Any]:
            try:
                while True:
                    await asyncio.Event().wait()
            except asyncio.CancelledError:
                await asyncio.sleep(0.12)
                try:
                    return await evidence.export_http_exchange_evidence(client, directory, **kwargs)
                finally:
                    settled.set()

        previous = evidence.HTTP_EVIDENCE_EXPORT_TIMEOUT_SECONDS
        evidence.HTTP_EVIDENCE_EXPORT_TIMEOUT_SECONDS = 0.01
        try:
            outcome = await state.reconcile_http_exchange_evidence(
                SyntheticClient({"17": _exchange()}), exporter=late
            )
            await settled.wait()
            await asyncio.sleep(0)
            return outcome
        finally:
            evidence.HTTP_EVIDENCE_EXPORT_TIMEOUT_SECONDS = previous
    negative = case
    if case == "negative-with-prior":
        await state.reconcile_http_exchange_evidence(SyntheticClient({"17": _exchange()}))
        negative = "outcome-missing"
    return await state.reconcile_http_exchange_evidence(
        SyntheticClient({"17": _exchange()}),
        exporter=functools.partial(_negative_export, negative=negative),
    )


def _write_exclusive(directory_fd: int, name: str, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    descriptor = os.open(name, flags, 0o600, dir_fd=directory_fd)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(payload)


def _publish_case(output_fd: int, case: str, source_directory: Path) -> dict[str, Any]:
    os.mkdir(case, 0o700, dir_fd=output_fd)
    case_fd = os.open(case, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=output_fd)
    files = {}
    try:
        for name in ("run.json", "vulnerabilities.json", evidence.HTTP_EXCHANGES_FILENAME):
            source = source_directory / name
            if source.exists():
                payload = source.read_bytes()
                _write_exclusive(case_fd, name, payload)
                files[name] = {"sha256": hashlib.sha256(payload).hexdigest(), "bytes": len(payload)}
            else:
                try:
                    os.stat(name, dir_fd=case_fd, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                raise FileExistsError(f"Unexpected fixture destination already exists: {name}")
    finally:
        os.close(case_fd)
    return files


async def generate(output: Path) -> dict[str, Any]:
    """Publish into an exclusively created private root; refuse existing paths.

    Directory descriptors keep publication attached to the directories we
    created. Exclusive, no-follow file creation also protects the summary.
    """
    output = output.absolute()
    output.mkdir(mode=0o700)
    output_fd = os.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    summary = {}
    previous_directory = Path.cwd()
    try:
        for case in STANDARD_CASES + NEGATIVE_CASES:
            with tempfile.TemporaryDirectory() as working:
                try:
                    os.chdir(working)
                    prefix = "task5-fix1" if case in STANDARD_CASES else "task5-fix2"
                    state = ReportState(run_name=f"{prefix}-{case}")
                    outcome = await _run_case(state, case)
                    files = _publish_case(output_fd, case, state.get_run_dir())
                    summary[case] = {
                        "run_name": state.run_name,
                        "status": outcome["status"],
                        "reason": outcome.get("reason"),
                        "exchanges": outcome["exchanges"],
                        "files": files,
                        "ordinary": {
                            finding["id"]: finding.get("http_exchange_ids", [])
                            for finding in state.vulnerability_reports
                        },
                        "pending": {
                            finding["id"]: finding.get("pending_http_exchange_ids", [])
                            for finding in state.vulnerability_reports
                        },
                    }
                finally:
                    os.chdir(previous_directory)
        payload = json.dumps(summary, indent=2).encode("utf-8")
        _write_exclusive(output_fd, "summary.json", payload)
        return summary
    finally:
        os.close(output_fd)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    os.environ.update(
        STRIX_SANDBOX_MODE="local",
        LYRASHIELD_RUN_RECORD_V1_1="1",
        LYRASHIELD_PENDING_HTTP_EVIDENCE="1",
    )
    summary = asyncio.run(generate(args.output_dir))
    print(  # noqa: T201 - CLI fixture summary
        json.dumps(
            {
                case: {"status": row["status"], "exchanges": row["exchanges"]}
                for case, row in summary.items()
            }
        )
    )


if __name__ == "__main__":
    main()
