"""Product-only validation and normalization for reporting fields."""

from __future__ import annotations

import logging
import re
from typing import Any


logger = logging.getLogger(__name__)

_CVSS_VALID = {
    "attack_vector": ["N", "A", "L", "P"],
    "attack_complexity": ["L", "H"],
    "privileges_required": ["N", "L", "H"],
    "user_interaction": ["N", "R"],
    "scope": ["U", "C"],
    "confidentiality": ["N", "L", "H"],
    "integrity": ["N", "L", "H"],
    "availability": ["N", "L", "H"],
}

_DEP_SEVERITY_FROM_CVSS = {
    (9.0, 10.0): "critical",
    (7.0, 9.0): "high",
    (4.0, 7.0): "medium",
    (0.0, 4.0): "low",
}


def extract_cwe(cwe: str) -> str:
    match = re.search(r"CWE-\d+", cwe)
    return match.group(0) if match else cwe.strip()


def validate_cwe(cwe: str) -> str | None:
    if not re.match(r"^CWE-\d+$", cwe):
        return f"invalid CWE format: '{cwe}' (expected 'CWE-NNN')"
    return None


def validate_cvss_breakdown(
    breakdown: Any,
    *,
    error_prefix: str = "",
) -> list[str]:
    """Check the 8 CVSS metrics are present with legal values."""
    if not isinstance(breakdown, dict) or not breakdown:
        return ["cvss_breakdown: must be an object with the 8 CVSS metrics"]
    errors: list[str] = []
    for name, valid in _CVSS_VALID.items():
        value = breakdown.get(name)
        if value not in valid:
            field = f"{error_prefix} {name}".strip()
            errors.append(f"Invalid {field}: {value}. Must be one of: {valid}")
    return errors


def calculate_cvss(breakdown: dict[str, str]) -> tuple[float, str, str]:
    try:
        from cvss import CVSS3  # noqa: PLC0415 - keep the optional scoring fallback

        vector = (
            f"CVSS:3.1/AV:{breakdown['attack_vector']}/AC:{breakdown['attack_complexity']}/"
            f"PR:{breakdown['privileges_required']}/UI:{breakdown['user_interaction']}/"
            f"S:{breakdown['scope']}/C:{breakdown['confidentiality']}/"
            f"I:{breakdown['integrity']}/A:{breakdown['availability']}"
        )
        cvss = CVSS3(vector)
        score = cvss.scores()[0]
        severity = cvss.severities()[0].lower()
    except Exception:
        logger.exception("Failed to calculate CVSS")
        return 7.5, "high", ""
    else:
        return score, severity, vector


def dependency_severity(advisory_cvss: float | None) -> tuple[float, str]:
    if advisory_cvss is None:
        return 0.0, "info"
    score = max(0.0, min(10.0, advisory_cvss))
    for (lo, hi), label in _DEP_SEVERITY_FROM_CVSS.items():
        if lo <= score < hi or (hi == 10.0 and score == 10.0):
            return score, label
    return score, "none"


def normalize_package_ecosystem(package_ecosystem: str | None) -> str | None:
    if not package_ecosystem:
        return None
    normalized = package_ecosystem.strip()
    return normalized or None


def build_dependency_metadata(
    *,
    package_name: str,
    installed_version: str,
    package_ecosystem: str | None,
    fixed_version: str | None,
) -> dict[str, Any]:
    metadata: dict[str, Any] = {
        "package_name": package_name.strip(),
        "installed_version": installed_version.strip(),
    }
    ecosystem = normalize_package_ecosystem(package_ecosystem)
    if ecosystem:
        metadata["package_ecosystem"] = ecosystem
    if fixed_version and fixed_version.strip():
        metadata["fixed_version"] = fixed_version.strip()
    return metadata
