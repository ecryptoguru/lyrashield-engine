"""SDK-native vulnerability-report deduplication."""

from __future__ import annotations

import logging
import re
from typing import Any


logger = logging.getLogger(__name__)


def _dependency_identity(report: dict[str, Any]) -> tuple[str, str, str] | None:
    metadata = report.get("dependency_metadata")
    if not isinstance(metadata, dict):
        return None

    raw_cve = report.get("cve")
    raw_package = metadata.get("package_name")
    if not raw_cve or not raw_package:
        return None

    cve = str(raw_cve).strip().upper()
    ecosystem = str(metadata.get("package_ecosystem") or "").strip().lower()
    package_name = str(raw_package).strip().lower()
    if not cve or not package_name:
        return None
    return cve, ecosystem, package_name


def _report_cve(report: dict[str, Any]) -> str:
    return str(report.get("cve") or "").strip().upper()


def _legacy_report_mentions_package(
    report: dict[str, Any],
    *,
    ecosystem: str,
    package_name: str,
) -> bool:
    fields = [
        "title",
        "description",
        "impact",
        "target",
        "technical_analysis",
        "poc_description",
        "evidence",
    ]
    haystack = " ".join(str(report.get(field) or "") for field in fields).lower()
    package_pattern = rf"(?<![\w@./-]){re.escape(package_name)}(?![\w@./-])"
    if re.search(package_pattern, haystack) is None:
        return False
    if not ecosystem:
        return True
    ecosystem_pattern = rf"(?<![\w@./-]){re.escape(ecosystem)}(?![\w@./-])"
    return re.search(ecosystem_pattern, haystack) is not None


def _check_dependency_duplicate(
    candidate: dict[str, Any],
    existing_reports: list[dict[str, Any]],
) -> dict[str, Any] | None:
    candidate_identity = _dependency_identity(candidate)
    if candidate_identity is None:
        return None

    cve, ecosystem, package_name = candidate_identity
    found_legacy_same_cve = False
    for report in existing_reports:
        report_identity = _dependency_identity(report)
        if report_identity is not None:
            report_cve, report_ecosystem, report_package_name = report_identity
            if (report_cve, report_package_name) != (cve, package_name):
                continue
            if report_ecosystem == ecosystem:
                return {
                    "is_duplicate": True,
                    "duplicate_id": str(report.get("id") or "")[:64],
                    "confidence": 1.0,
                    "reason": "Same dependency CVE/package identity",
                }
            if not report_ecosystem or not ecosystem:
                return {
                    "is_duplicate": True,
                    "duplicate_id": str(report.get("id") or "")[:64],
                    "confidence": 1.0,
                    "reason": "Same dependency CVE/package identity with missing ecosystem",
                }
            continue

        if _report_cve(report) != cve:
            continue
        found_legacy_same_cve = True
        if _legacy_report_mentions_package(
            report,
            ecosystem=ecosystem,
            package_name=package_name,
        ):
            return {
                "is_duplicate": True,
                "duplicate_id": str(report.get("id") or "")[:64],
                "confidence": 1.0,
                "reason": "Same dependency CVE/package identity in legacy report",
            }

    if found_legacy_same_cve:
        return None

    package_label = f"{ecosystem}/{package_name}" if ecosystem else package_name
    return {
        "is_duplicate": False,
        "duplicate_id": "",
        "confidence": 1.0,
        "reason": f"No existing dependency report for {cve} in {package_label}",
    }


def _normalized_text(value: Any) -> str:
    return " ".join(str(value or "").lower().split())


def _dynamic_identity(report: dict[str, Any]) -> tuple[str, ...] | None:
    locations = report.get("code_locations")
    primary_location = ""
    if isinstance(locations, list) and locations and isinstance(locations[0], dict):
        first = locations[0]
        primary_location = ":".join(
            [
                _normalized_text(first.get("file")),
                str(first.get("start_line") or ""),
                str(first.get("end_line") or ""),
            ]
        )
    endpoint = _normalized_text(report.get("endpoint"))
    target = _normalized_text(report.get("target"))
    if not endpoint and not primary_location:
        return None
    return (
        target,
        endpoint,
        _normalized_text(report.get("method")),
        primary_location,
        _normalized_text(report.get("cwe")),
        _normalized_text(report.get("title")),
    )


async def check_duplicate(
    candidate: dict[str, Any], existing_reports: list[dict[str, Any]]
) -> dict[str, Any]:
    if not existing_reports:
        return {
            "is_duplicate": False,
            "duplicate_id": "",
            "confidence": 1.0,
            "reason": "No existing reports to compare against",
        }

    dependency_duplicate = _check_dependency_duplicate(candidate, existing_reports)
    if dependency_duplicate is not None:
        return dependency_duplicate

    candidate_identity = _dynamic_identity(candidate)
    if candidate_identity is not None:
        for report in existing_reports:
            if _dynamic_identity(report) == candidate_identity:
                return {
                    "is_duplicate": True,
                    "duplicate_id": str(report.get("id") or "")[:64],
                    "confidence": 1.0,
                    "reason": "Exact target, location, weakness, and title identity",
                }

    return {
        "is_duplicate": False,
        "duplicate_id": "",
        "confidence": 1.0,
        "reason": "No exact deterministic report identity matched",
    }
