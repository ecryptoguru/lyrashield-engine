"""Direct regression tests for evidence normalization and manifest contracts."""

from __future__ import annotations

import hashlib
import json
from typing import TYPE_CHECKING, Any

import pytest

from lyrashield.artifacts import evidence


if TYPE_CHECKING:
    from pathlib import Path


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        ("17", "must be a list"),
        ([17], "[0] must be a string"),
        (["  "], "[0] cannot be empty"),
        (["1" * (evidence.MAX_HTTP_EXCHANGE_ID_CHARS + 1)], "characters or fewer"),
        (["1\n7"], "visible ASCII"),
        (["request-17"], "numeric proxy request id"),
    ],
)
def test_http_exchange_id_normalizer_rejects_invalid_values(raw: Any, message: str) -> None:
    normalized, errors = evidence.normalize_http_exchange_ids(raw)

    assert normalized is None
    assert any(message in error for error in errors)


def test_http_exchange_id_normalizer_trims_deduplicates_and_preserves_order() -> None:
    assert evidence.normalize_http_exchange_ids([" 17 ", "18", "17", " 19 "]) == (
        ["17", "18", "19"],
        [],
    )
    assert evidence.normalize_http_exchange_ids(None) == (None, [])
    assert evidence.normalize_http_exchange_ids([]) == ([], [])


def test_http_exchange_id_normalizer_rejects_too_many_distinct_ids() -> None:
    raw = [str(index) for index in range(evidence.MAX_HTTP_EXCHANGE_IDS + 1)]

    normalized, errors = evidence.normalize_http_exchange_ids(raw)

    assert normalized is None
    assert any("distinct request ids" in error for error in errors)


def test_http_exchange_id_normalizer_accepts_inclusive_bounds() -> None:
    longest_id = "9" * evidence.MAX_HTTP_EXCHANGE_ID_CHARS
    ids = [str(index) for index in range(evidence.MAX_HTTP_EXCHANGE_IDS)]

    assert evidence.normalize_http_exchange_ids([longest_id]) == ([longest_id], [])
    assert evidence.normalize_http_exchange_ids(ids) == (ids, [])


@pytest.mark.parametrize(
    ("raw", "expected", "error"),
    [
        (None, None, None),
        (" HIGH ", "high", None),
        ("Medium", "medium", None),
        ("unknown", None, "Invalid confidence"),
        (False, None, "confidence must be a string"),
    ],
)
def test_confidence_normalizer(raw: Any, expected: str | None, error: str | None) -> None:
    normalized, errors = evidence.normalize_confidence(raw)

    assert normalized == expected
    if error is None:
        assert errors == []
    else:
        assert any(error in message for message in errors)


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        (True, "must be an object or a 0-10 score"),
        (-0.1, "between 0.0 and 10.0"),
        (10.1, "between 0.0 and 10.0"),
        ("7.5", "must be an object"),
        ([], "must be an object"),
        ({}, "score is required"),
        ({"score": "7.5"}, "score is required"),
        ({"score": True}, "score is required"),
        ({"score": 10.1}, "between 0.0 and 10.0"),
        ({"score": 5, "vector": 42}, "vector must be a CVSS vector string"),
        ({"score": 5, "vector": "not-a-vector"}, "vector must be a CVSS vector string"),
        ({"score": 5, "source": 42}, "source must be a string"),
        ({"score": 5, "metric_reasoning": []}, "metric_reasoning must be a string"),
    ],
)
def test_advisory_cvss_normalizer_rejects_invalid_values(raw: Any, message: str) -> None:
    normalized, errors = evidence.normalize_advisory_cvss(raw)

    assert normalized is None
    assert any(message in error for error in errors)


def test_advisory_cvss_normalizer_accepts_bounds_and_truncates_text() -> None:
    assert evidence.normalize_advisory_cvss(0) == ({"score": 0.0}, [])
    assert evidence.normalize_advisory_cvss(10.0) == ({"score": 10.0}, [])

    normalized, errors = evidence.normalize_advisory_cvss(
        {
            "score": 7,
            "vector": " CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H ",
            "source": " advisory ",
            "metric_reasoning": "r" * (evidence.MAX_METRIC_REASONING_CHARS + 1),
        }
    )

    assert errors == []
    assert normalized == {
        "score": 7.0,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "source": "advisory",
        "metric_reasoning": "r" * evidence.MAX_METRIC_REASONING_CHARS,
    }


def test_advisory_cvss_normalizer_omits_blank_optional_text() -> None:
    assert evidence.normalize_advisory_cvss(
        {"score": 5, "source": "  ", "metric_reasoning": " "}
    ) == ({"score": 5.0}, [])


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        ("  ", "cannot be an empty string"),
        (42, "must be an object or a statement string"),
        ({}, "statement is required"),
        ({"statement": " "}, "statement is required"),
        ({"statement": "ok", "method": 42}, "method must be a string"),
        ({"statement": "ok", "evidence_refs": "17"}, "evidence_refs must be a list"),
        ({"statement": "ok", "evidence_refs": [None]}, "evidence_refs[0] must be a string"),
        ({"statement": "ok", "evidence_refs": [" "]}, "evidence_refs[0] must be a string"),
    ],
)
def test_fix_verification_normalizer_rejects_invalid_values(raw: Any, message: str) -> None:
    normalized, errors = evidence.normalize_fix_verification(raw)

    assert normalized is None
    assert any(message in error for error in errors)


def test_fix_verification_normalizer_wraps_and_bounds_fields() -> None:
    assert evidence.normalize_fix_verification("  checked  ") == (
        {"kind": evidence.FIX_VERIFICATION_KIND, "statement": "checked"},
        [],
    )

    normalized, errors = evidence.normalize_fix_verification(
        {
            "statement": "s" * (evidence.MAX_EVIDENCE_FIELD_CHARS + 1),
            "method": "m" * 257,
            "evidence_refs": ["r" * (evidence.MAX_HTTP_EXCHANGE_ID_CHARS + 1)],
        }
    )

    assert errors == []
    assert normalized == {
        "kind": evidence.FIX_VERIFICATION_KIND,
        "statement": "s" * evidence.MAX_EVIDENCE_FIELD_CHARS,
        "method": "m" * 256,
        "evidence_refs": ["r" * evidence.MAX_HTTP_EXCHANGE_ID_CHARS],
    }


def test_fix_verification_normalizer_omits_blank_optional_fields() -> None:
    assert evidence.normalize_fix_verification(
        {"statement": " checked ", "method": " ", "evidence_refs": []}
    ) == ({"kind": evidence.FIX_VERIFICATION_KIND, "statement": "checked"}, [])


def test_fix_verification_normalizer_accepts_evidence_ref_limit() -> None:
    refs = [str(index) for index in range(evidence.MAX_HTTP_EXCHANGE_IDS)]

    normalized, errors = evidence.normalize_fix_verification(
        {"statement": "checked", "evidence_refs": refs}
    )

    assert errors == []
    assert normalized == {
        "kind": evidence.FIX_VERIFICATION_KIND,
        "statement": "checked",
        "evidence_refs": refs,
    }


def test_fix_verification_normalizer_rejects_too_many_evidence_refs() -> None:
    normalized, errors = evidence.normalize_fix_verification(
        {"statement": "checked", "evidence_refs": ["1"] * (evidence.MAX_HTTP_EXCHANGE_IDS + 1)}
    )

    assert normalized is None
    assert any("bounded to" in error for error in errors)


def _original_finding() -> dict[str, Any]:
    return {
        "id": "finding-1",
        "timestamp": "2026-01-01T00:00:00Z",
        "finding_class": "application",
        "agent_id": "agent-1",
        "agent_name": "reviewer",
    }


def _revised_finding(**changes: Any) -> dict[str, Any]:
    return {
        **_original_finding(),
        "title": "Updated title",
        "severity": "HIGH",
        "update_history": [],
        **changes,
    }


def test_revised_finding_accepts_valid_revision_and_history_limit() -> None:
    revised = _revised_finding(
        update_history=[{} for _ in range(evidence.MAX_UPDATE_HISTORY_ENTRIES)]
    )

    assert evidence.validate_revised_finding(revised, _original_finding()) == []


def test_revised_finding_rejects_missing_history() -> None:
    revised = _revised_finding()
    revised.pop("update_history")

    errors = evidence.validate_revised_finding(revised, _original_finding())

    assert any("history missing or exceeds its bound" in error for error in errors)


@pytest.mark.parametrize("field", ["id", "timestamp", "finding_class", "agent_id", "agent_name"])
def test_revised_finding_rejects_identity_or_authorship_mutation(field: str) -> None:
    revised = _revised_finding(**{field: "changed"})

    errors = evidence.validate_revised_finding(revised, _original_finding())

    assert any(f"creation-time field '{field}'" in error for error in errors)


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"title": " "}, "'title' empty"),
        ({"title": 1}, "'title' empty"),
        ({"severity": "urgent"}, "'severity' invalid"),
        ({"severity": None}, "'severity' invalid"),
        ({"update_history": None}, "history missing or exceeds its bound"),
        ({"update_history": ()}, "history missing or exceeds its bound"),
        (
            {"update_history": [{} for _ in range(evidence.MAX_UPDATE_HISTORY_ENTRIES + 1)]},
            "history missing or exceeds its bound",
        ),
    ],
)
def test_revised_finding_rejects_invalid_fields_and_history(
    changes: dict[str, Any], message: str
) -> None:
    errors = evidence.validate_revised_finding(_revised_finding(**changes), _original_finding())

    assert any(message in error for error in errors)


def test_result_manifest_is_deterministic_and_checksums_sorted_vulnerabilities(
    tmp_path: Path,
) -> None:
    first_dir = tmp_path / "first"
    second_dir = tmp_path / "second"
    contents = {
        "vulnerabilities/a.md": b"a",
        "vulnerabilities/z.md": b"z",
        "findings.sarif": b"sarif",
    }
    for run_dir, order in (
        (
            first_dir,
            ("vulnerabilities/z.md", "findings.sarif", "vulnerabilities/a.md"),
        ),
        (
            second_dir,
            ("vulnerabilities/a.md", "vulnerabilities/z.md", "findings.sarif"),
        ),
    ):
        for relative_path in order:
            path = run_dir / relative_path
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(contents[relative_path])

    first = evidence.build_result_manifest(first_dir)
    second = evidence.build_result_manifest(second_dir)

    assert json.dumps(first) == json.dumps(second)
    artifacts = first["artifacts"]
    assert artifacts["findings.sarif"] == {
        "path": "findings.sarif",
        "sha256": hashlib.sha256(b"sarif").hexdigest(),
        "bytes": 5,
    }
    assert list(artifacts["vulnerabilities/"]["files"]) == ["a.md", "z.md"]
    assert artifacts["vulnerabilities/"]["files"] == {
        "a.md": hashlib.sha256(b"a").hexdigest(),
        "z.md": hashlib.sha256(b"z").hexdigest(),
    }
