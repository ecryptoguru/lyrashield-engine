"""Sanitized public/durable artifacts (C7, I7, I9, I15).

Sentinels mark sensitive substrings (credentials, host paths, URL userinfo,
query tokens, raw instructions). They must be absent from every durable or
public projection: run.json, vulnerabilities JSON/MD/CSV, SARIF, and recovery
logs — while stable identifiers and severities survive every projection.
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Any

import pytest
from agents.run import RunResult

from lyrashield.artifacts import state as state_module
from lyrashield.artifacts.sarif import build_sarif_report
from lyrashield.artifacts.state import ReportState
from lyrashield.lifecycle import execution


if TYPE_CHECKING:
    from pathlib import Path


SENTINEL = "ZX9SENTINELQW"  # unique marker for sensitive substrings


def _artifact_texts(run_dir: Path) -> str:
    chunks: list[str] = []
    for path in sorted(run_dir.rglob("*")):
        if path.is_file():
            try:
                chunks.append(path.read_text(encoding="utf-8"))
            except (UnicodeDecodeError, OSError):
                continue
    return "\n".join(chunks)


@pytest.fixture
def report_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> ReportState:
    monkeypatch.setattr(state_module, "run_dir_for", lambda _n: tmp_path)
    return ReportState(run_name="sanitize-run")


def test_sensitive_sentinels_absent_from_all_durable_artifacts(
    report_state: ReportState, tmp_path: Path
) -> None:
    report_state.set_scan_config(
        {
            "targets": [
                {
                    "type": "web_application",
                    "details": {
                        "target_url": f"https://user:{SENTINEL}@app.example.com/x?token={SENTINEL}&page=2"
                    },
                },
                {
                    "type": "repository",
                    "details": {
                        "target_repo": f"https://git:{SENTINEL}@github.com/acme/widget.git",
                        "cloned_repo_path": f"/Users/operator/{SENTINEL}/widget",
                    },
                },
                {
                    "type": "local_code",
                    "details": {"target_path": f"/Users/operator/src/{SENTINEL}"},
                },
            ],
            "user_instructions": f"Attack {SENTINEL} and report password={SENTINEL}",
            "scan_mode": "deep",
            "local_sources": [
                {
                    "workspace_subdir": "repo",
                    "source_path": f"/Users/operator/{SENTINEL}/repo",
                    "mount": True,
                }
            ],
        }
    )
    report_state.add_vulnerability_report(
        title=f"SQLi via token={SENTINEL}",
        severity="critical",
        description=f"Injected at /Users/op/{SENTINEL}/app.py using password={SENTINEL}",
        target=f"https://admin:{SENTINEL}@app.example.com/login?session={SENTINEL}",
        endpoint=f"https://app.example.com/api?api_key={SENTINEL}",
        evidence=f"curl -H 'Authorization: Bearer {SENTINEL}' /Users/op/{SENTINEL}/ev",
        poc_description=f"PoC at ~/src/{SENTINEL}/poc.py",
        poc_script_code=f"run(token={SENTINEL})",
        remediation_steps=f"Rotate token={SENTINEL} at /home/op/{SENTINEL}",
        assumptions=f"Assume api_key={SENTINEL} rotates",
        cvss_breakdown={
            "attack_vector": "N",
            "attack_complexity": "L",
            "privileges_required": "N",
            "user_interaction": "N",
            "scope": "U",
            "confidentiality": "H",
            "integrity": "H",
            "availability": "H",
        },
        code_locations=[
            {
                "file": "src/app.py",
                "start_line": 10,
                "snippet": f"query?token={SENTINEL}",
                "fix_before": "old_call()",
                "fix_after": "new_call()",
            }
        ],
        dependency_metadata={"advisory": f"token={SENTINEL}"},
        agent_name=f"agent password={SENTINEL}",
        agent_id="agent-1",
    )
    report_state.update_scan_final_fields(
        executive_summary=f"Summary references password={SENTINEL} at /Users/op/{SENTINEL}",
        methodology="OWASP",
        technical_analysis="ta",
        recommendations=f"Rotate secret={SENTINEL}",
    )

    blob = _artifact_texts(tmp_path)
    assert SENTINEL not in blob

    # run.json specifics: no raw instruction, no host paths.
    run_record = json.loads((tmp_path / "run.json").read_text(encoding="utf-8"))
    assert run_record["instruction"] is None
    assert run_record["instruction_chars"] > 0
    sources = run_record["local_sources"]
    assert sources == [{"workspace_subdir": "repo", "mount": True}]
    targets_blob = json.dumps(run_record["targets_info"])
    assert SENTINEL not in targets_blob
    assert "cloned_repo_path" not in targets_blob

    # Stable identity and severity survive every projection.
    vulns = json.loads((tmp_path / "vulnerabilities.json").read_text(encoding="utf-8"))
    assert vulns[0]["id"] == "vuln-0001"
    assert vulns[0]["severity"] == "critical"
    sarif = json.loads((tmp_path / "findings.sarif").read_text(encoding="utf-8"))
    result = sarif["runs"][0]["results"][0]
    assert result["level"] == "error"
    assert SENTINEL not in json.dumps(sarif)


def test_public_sarif_carries_only_lyrashield_owned_naming() -> None:
    sarif = build_sarif_report([{"id": "vuln-0001", "title": "XSS", "severity": "high"}])
    blob = json.dumps(sarif).lower()
    assert "lyrashield" in blob
    assert "strix" not in blob
    assert "strix.ai" not in blob
    driver = sarif["runs"][0]["tool"]["driver"]
    assert driver["name"] == "LyraShield"
    assert driver["informationUri"] == "https://lyrashieldai.com"


def test_sarif_class_fingerprint_keeps_value_under_neutral_key() -> None:
    sarif = build_sarif_report(
        [{"id": "vuln-0001", "title": "SQL injection in search", "severity": "high"}]
    )
    properties = sarif["runs"][0]["results"][0]["properties"]
    assert "strix_vuln_class_hash" not in properties
    assert properties["lyrashield_vuln_class_hash"]


def test_recovery_logging_is_metadata_only(caplog: pytest.LogCaptureFixture) -> None:
    """I9: recovery logs describe output type/length, never raw model output."""

    class _FakeResult(RunResult):
        def __init__(self) -> None:
            self.final_output = f"model says {SENTINEL}"

    assert not hasattr(execution, "_final_output_preview")
    metadata = execution._final_output_metadata(_FakeResult())
    assert SENTINEL not in metadata
    assert "str" in metadata

    with caplog.at_level(logging.WARNING, logger="lyrashield.lifecycle.execution"):
        # The recovery path itself is exercised in test_execution.py; here the
        # contract is that the helper used for that log cannot leak output.
        logger = logging.getLogger("lyrashield.lifecycle.execution")
        logger.warning("forcing tool continuation: %s", metadata)
    assert SENTINEL not in caplog.text


def test_whitebox_mode_preserves_workspace_paths_but_strips_host_paths(
    report_state: ReportState, tmp_path: Path
) -> None:
    report_state.set_scan_config(
        {"targets": [{"type": "local_code", "details": {"target_path": "/workspace/repo"}}]}
    )
    report_state.add_vulnerability_report(
        title="Path handling",
        severity="medium",
        description=f"see /workspace/repo/app.py and /Users/op/{SENTINEL}/notes.txt",
    )
    vulns = json.loads((tmp_path / "vulnerabilities.json").read_text(encoding="utf-8"))
    description: Any = vulns[0]["description"]
    assert "/workspace/repo/app.py" in description
    assert SENTINEL not in description
