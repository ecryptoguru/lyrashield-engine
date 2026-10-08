# Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
import argparse
import json
import logging
import re
import secrets
import sys
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlparse

import docker
from docker.errors import DockerException, ImageNotFound
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from strix.config import load_settings

from . import local_sources as _local_sources
from . import source_acquisition as _source_acquisition


logger = logging.getLogger(__name__)
TARGET_TYPE_CHOICES = _local_sources.TARGET_TYPE_CHOICES

# Keep historical imports stable while implementation lives in focused modules.
assign_workspace_subdirs = _local_sources.assign_workspace_subdirs
build_mount_targets_info = _local_sources.build_mount_targets_info
collect_local_sources = _local_sources.collect_local_sources
dedupe_local_targets = _local_sources.dedupe_local_targets
derive_local_base_name = _local_sources.derive_local_base_name
derive_repo_base_name = _local_sources.derive_repo_base_name
directory_size_bytes = _local_sources.directory_size_bytes
find_oversized_local_targets = _local_sources.find_oversized_local_targets
infer_target_type = _local_sources.infer_target_type
is_whitebox_scan = _local_sources.is_whitebox_scan
read_target_list_file = _local_sources.read_target_list_file
resolve_target_type = _local_sources.resolve_target_type
rewrite_localhost_targets = _local_sources.rewrite_localhost_targets
sanitize_name = _local_sources.sanitize_name

DiffEntry = _source_acquisition.DiffEntry
DiffScopeResult = _source_acquisition.DiffScopeResult
RepoDiffScope = _source_acquisition.RepoDiffScope
SourcePreflightError = _source_acquisition.SourcePreflightError
_is_full_git_commit_sha = _source_acquisition._is_full_git_commit_sha
_is_git_object_id = _source_acquisition._is_git_object_id
_read_only_head_revision = _source_acquisition._read_only_head_revision
build_diff_scope_instruction = _source_acquisition.build_diff_scope_instruction
clone_repository = _source_acquisition.clone_repository
resolve_diff_scope_context = _source_acquisition.resolve_diff_scope_context
validate_git_object_id = _source_acquisition.validate_git_object_id


def _as_str_dict(value: Any) -> dict[str, Any]:
    return cast("dict[str, Any]", value) if isinstance(value, dict) else {}


def _as_str_or_none(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def get_severity_color(severity: str) -> str:
    severity_colors = {
        "critical": "#dc2626",
        "high": "#ea580c",
        "medium": "#d97706",
        "low": "#65a30d",
        "info": "#0284c7",
    }
    return severity_colors.get(severity, "#6b7280")


def get_cvss_color(cvss_score: float) -> str:
    if cvss_score >= 9.0:
        return "#dc2626"
    if cvss_score >= 7.0:
        return "#ea580c"
    if cvss_score >= 4.0:
        return "#d97706"
    if cvss_score >= 0.1:
        return "#65a30d"
    return "#6b7280"


def format_token_count(count: float | None) -> str:
    value = int(count or 0)
    if value >= 1_000_000:
        return f"{value / 1_000_000:.1f}M"
    if value >= 1_000:
        return f"{value / 1_000:.1f}K"
    return str(value)


def format_vulnerability_report(report: dict[str, Any]) -> Text:
    field_style = "bold #4ade80"

    text = Text()

    title = report.get("title", "")
    if title:
        text.append("Vulnerability Report", style="bold #ea580c")
        text.append("\n\n")
        text.append("Title: ", style=field_style)
        text.append(title)

    severity = report.get("severity", "")
    if severity:
        text.append("\n\n")
        text.append("Severity: ", style=field_style)
        severity_color = get_severity_color(severity.lower())
        text.append(severity.upper(), style=f"bold {severity_color}")

    cvss = report.get("cvss")
    if cvss is not None:
        text.append("\n\n")
        text.append("CVSS Score: ", style=field_style)
        cvss_color = get_cvss_color(cvss)
        text.append(f"{cvss:.1f}", style=f"bold {cvss_color}")

    target = report.get("target")
    if target:
        text.append("\n\n")
        text.append("Target: ", style=field_style)
        text.append(target)

    endpoint = report.get("endpoint")
    if endpoint:
        text.append("\n\n")
        text.append("Endpoint: ", style=field_style)
        text.append(endpoint)

    method = report.get("method")
    if method:
        text.append("\n\n")
        text.append("Method: ", style=field_style)
        text.append(method)

    cve = report.get("cve")
    if cve:
        text.append("\n\n")
        text.append("CVE: ", style=field_style)
        text.append(cve)

    cvss_breakdown = _as_str_dict(report.get("cvss_breakdown"))
    if cvss_breakdown:
        text.append("\n\n")
        cvss_parts: list[str] = []
        if cvss_breakdown.get("attack_vector"):
            cvss_parts.append(f"AV:{cvss_breakdown['attack_vector']}")
        if cvss_breakdown.get("attack_complexity"):
            cvss_parts.append(f"AC:{cvss_breakdown['attack_complexity']}")
        if cvss_breakdown.get("privileges_required"):
            cvss_parts.append(f"PR:{cvss_breakdown['privileges_required']}")
        if cvss_breakdown.get("user_interaction"):
            cvss_parts.append(f"UI:{cvss_breakdown['user_interaction']}")
        if cvss_breakdown.get("scope"):
            cvss_parts.append(f"S:{cvss_breakdown['scope']}")
        if cvss_breakdown.get("confidentiality"):
            cvss_parts.append(f"C:{cvss_breakdown['confidentiality']}")
        if cvss_breakdown.get("integrity"):
            cvss_parts.append(f"I:{cvss_breakdown['integrity']}")
        if cvss_breakdown.get("availability"):
            cvss_parts.append(f"A:{cvss_breakdown['availability']}")
        if cvss_parts:
            text.append("CVSS Vector: ", style=field_style)
            text.append("/".join(cvss_parts), style="dim")

    description = report.get("description")
    if description:
        text.append("\n\n")
        text.append("Description", style=field_style)
        text.append("\n")
        text.append(description)

    impact = report.get("impact")
    if impact:
        text.append("\n\n")
        text.append("Impact", style=field_style)
        text.append("\n")
        text.append(impact)

    technical_analysis = report.get("technical_analysis")
    if technical_analysis:
        text.append("\n\n")
        text.append("Technical Analysis", style=field_style)
        text.append("\n")
        text.append(technical_analysis)

    poc_description = report.get("poc_description")
    if poc_description:
        text.append("\n\n")
        text.append("PoC Description", style=field_style)
        text.append("\n")
        text.append(poc_description)

    poc_script_code = report.get("poc_script_code")
    if poc_script_code:
        text.append("\n\n")
        text.append("PoC Code", style=field_style)
        text.append("\n")
        text.append(poc_script_code, style="dim")

    code_locations = report.get("code_locations")
    if code_locations:
        text.append("\n\n")
        text.append("Code Locations", style=field_style)
        for i, loc in enumerate(code_locations):
            text.append("\n\n")
            text.append(f"  Location {i + 1}: ", style="dim")
            text.append(loc.get("file", "unknown"), style="bold")
            start = loc.get("start_line")
            end = loc.get("end_line")
            if start is not None:
                if end and end != start:
                    text.append(f":{start}-{end}")
                else:
                    text.append(f":{start}")
            if loc.get("label"):
                text.append(f"\n  {loc['label']}", style="italic dim")
            if loc.get("snippet"):
                text.append("\n  ")
                text.append(loc["snippet"], style="dim")
            if loc.get("fix_before") or loc.get("fix_after"):
                text.append("\n  Fix:")
                if loc.get("fix_before"):
                    text.append("\n  - ", style="dim")
                    text.append(loc["fix_before"], style="dim")
                if loc.get("fix_after"):
                    text.append("\n  + ", style="dim")
                    text.append(loc["fix_after"], style="dim")

    remediation_steps = report.get("remediation_steps")
    if remediation_steps:
        text.append("\n\n")
        text.append("Remediation", style=field_style)
        text.append("\n")
        text.append(remediation_steps)

    return text


def _build_vulnerability_stats(stats_text: Text, report_state: Any) -> None:
    vuln_count = len(report_state.vulnerability_reports)

    if vuln_count > 0:
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for report in report_state.vulnerability_reports:
            severity = report.get("severity", "").lower()
            if severity in severity_counts:
                severity_counts[severity] += 1

        stats_text.append("Vulnerabilities  ", style="bold red")

        severity_parts: list[Text] = []
        for severity in ["critical", "high", "medium", "low", "info"]:
            count = severity_counts[severity]
            if count > 0:
                severity_color = get_severity_color(severity)
                severity_text = Text()
                severity_text.append(f"{severity.upper()}: ", style=severity_color)
                severity_text.append(str(count), style=f"bold {severity_color}")
                severity_parts.append(severity_text)

        for i, part in enumerate(severity_parts):
            stats_text.append(part)
            if i < len(severity_parts) - 1:
                stats_text.append(" | ", style="dim white")

        stats_text.append(" (Total: ", style="dim white")
        stats_text.append(str(vuln_count), style="bold yellow")
        stats_text.append(")", style="dim white")
        stats_text.append("\n")
    else:
        stats_text.append("Vulnerabilities  ", style="bold #22c55e")
        stats_text.append("0", style="bold white")
        stats_text.append(" (No exploitable vulnerabilities detected)", style="dim green")
        stats_text.append("\n")


def _llm_usage(report_state: Any) -> dict[str, Any]:
    if hasattr(report_state, "get_total_llm_usage"):
        usage = report_state.get_total_llm_usage()
        return _as_str_dict(usage)
    usage = getattr(report_state, "run_record", {}).get("llm_usage")
    return _as_str_dict(usage)


def _is_subscription(report_state: Any) -> bool:
    """Whether this run uses a model subscription (no metered cost).

    Prefers the run record so it's correct for hydrated/resumed runs; falls back
    to current settings.
    """
    record = getattr(report_state, "run_record", None)
    if isinstance(record, dict):
        record = _as_str_dict(record)
        if record.get("auth_mode"):
            return record.get("auth_mode") == "subscription"
    from strix.config import codex

    return codex.auth_mode(load_settings().llm.model) == "subscription"


def _int_stat(usage: dict[str, Any], key: str) -> int:
    try:
        return max(0, int(usage.get(key) or 0))
    except (TypeError, ValueError):
        return 0


def _float_stat(usage: dict[str, Any], key: str) -> float:
    try:
        value = float(usage.get(key) or 0.0)
    except (TypeError, ValueError):
        return 0.0
    return value if value > 0 else 0.0


def _detail_value(usage: dict[str, Any], detail_key: str, value_key: str) -> int:
    details = usage.get(detail_key)
    if isinstance(details, list):
        details = _as_str_dict(details[0]) if details and isinstance(details[0], dict) else {}
    if not isinstance(details, dict):
        return 0
    details = _as_str_dict(details)
    return _int_stat(details, value_key)


def _build_llm_usage_stats(
    stats_text: Text,
    report_state: Any,
    *,
    live: bool = False,
) -> None:
    subscription = _is_subscription(report_state)
    usage = _llm_usage(report_state)
    if not usage or _int_stat(usage, "requests") <= 0:
        stats_text.append("\n")
        stats_text.append("Cost ", style="dim")
        if subscription:
            stats_text.append("$0.00 ", style="#22c55e")
            stats_text.append("(subscription) ", style="dim")
        else:
            stats_text.append("$0.0000 ", style="#fbbf24")
        stats_text.append("· ", style="dim white")
        stats_text.append("Tokens ", style="dim")
        stats_text.append("0", style="white")
        return

    input_tokens = _int_stat(usage, "input_tokens")
    output_tokens = _int_stat(usage, "output_tokens")
    cached_tokens = _detail_value(usage, "input_tokens_details", "cached_tokens")
    cost = _float_stat(usage, "cost")

    stats_text.append("\n")
    stats_text.append("Input Tokens ", style="dim")
    stats_text.append(format_token_count(input_tokens), style="white")

    if live or cached_tokens > 0:
        stats_text.append("  ·  ", style="dim white")
        stats_text.append("Cached Tokens ", style="dim")
        stats_text.append(format_token_count(cached_tokens), style="white")

    separator = "\n" if live else "  ·  "
    stats_text.append(separator, style="dim white")
    stats_text.append("Output Tokens ", style="dim")
    stats_text.append(format_token_count(output_tokens), style="white")

    if subscription:
        stats_text.append("  ·  ", style="dim white")
        stats_text.append("Cost ", style="dim")
        stats_text.append("$0.00", style="#22c55e")
        stats_text.append(" (subscription)", style="dim")
    elif live or cost > 0:
        stats_text.append("  ·  ", style="dim white")
        stats_text.append("Cost ", style="dim")
        stats_text.append(f"${cost:.4f}", style="#fbbf24")


def build_final_stats_text(report_state: Any) -> Text:
    stats_text = Text()
    if not report_state:
        return stats_text

    _build_vulnerability_stats(stats_text, report_state)
    _build_llm_usage_stats(stats_text, report_state)

    return stats_text


def build_live_stats_text(report_state: Any) -> Text:
    stats_text = Text()
    if not report_state:
        return stats_text

    model = load_settings().llm.model or "unknown"
    stats_text.append("Model ", style="dim")
    stats_text.append(str(model), style="white")
    if _is_subscription(report_state):
        stats_text.append("  ·  ", style="dim white")
        stats_text.append("ChatGPT subscription", style="#22c55e")
    stats_text.append("\n")

    vuln_count = len(report_state.vulnerability_reports)
    stats_text.append("Vulnerabilities ", style="dim")
    stats_text.append(f"{vuln_count}", style="white")
    stats_text.append("\n")
    if vuln_count > 0:
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for report in report_state.vulnerability_reports:
            severity = report.get("severity", "").lower()
            if severity in severity_counts:
                severity_counts[severity] += 1

        severity_parts: list[Text] = []
        for severity in ["critical", "high", "medium", "low", "info"]:
            count = severity_counts[severity]
            if count > 0:
                severity_color = get_severity_color(severity)
                severity_text = Text()
                severity_text.append(f"{severity.upper()}: ", style=severity_color)
                severity_text.append(str(count), style=f"bold {severity_color}")
                severity_parts.append(severity_text)

        for i, part in enumerate(severity_parts):
            stats_text.append(part)
            if i < len(severity_parts) - 1:
                stats_text.append(" | ", style="dim white")

        stats_text.append("\n")

    _build_llm_usage_stats(stats_text, report_state, live=True)

    return stats_text


def build_tui_stats_text(report_state: Any) -> Text:
    stats_text = Text()
    if not report_state:
        return stats_text

    model = load_settings().llm.model or "unknown"
    stats_text.append(str(model), style="white")
    subscription = _is_subscription(report_state)
    if subscription:
        stats_text.append("\n")
        stats_text.append("ChatGPT subscription", style="#22c55e")

    usage = _llm_usage(report_state)
    if usage and _int_stat(usage, "total_tokens") > 0:
        stats_text.append("\n")
        stats_text.append(
            f"{format_token_count(_int_stat(usage, 'total_tokens'))} tokens",
            style="white",
        )
        cost = _float_stat(usage, "cost")
        if subscription:
            stats_text.append(" · ", style="white")
            stats_text.append("$0.00", style="white")
        elif cost > 0:
            stats_text.append(" · ", style="white")
            stats_text.append(f"${cost:.2f}", style="white")

    caido_url = getattr(report_state, "caido_url", None)
    if caido_url:
        stats_text.append("\n")
        stats_text.append("Caido: ", style="bold white")
        stats_text.append(caido_url, style="white")

    return stats_text


def _slugify_for_run_name(text: str, max_length: int = 32) -> str:
    text = text.lower().strip()
    text = re.sub(r"[^a-z0-9]+", "-", text)
    text = text.strip("-")
    if len(text) > max_length:
        text = text[:max_length].rstrip("-")
    return text or "pentest"


def _derive_target_label_for_run_name(targets_info: list[dict[str, Any]] | None) -> str:
    if not targets_info:
        return "pentest"

    first = targets_info[0]
    target_type = str(first.get("type") or "")
    details = _as_str_dict(first.get("details"))
    original = str(first.get("original", "") or "")

    if target_type == "web_application":
        url = str(details.get("target_url", original) or original)
        try:
            parsed = urlparse(url)
            return str(parsed.netloc or parsed.path or url)
        except Exception:
            return str(url)

    if target_type == "repository":
        repo = str(details.get("target_repo", original) or original)
        parsed = urlparse(repo)
        path = parsed.path or repo
        name = path.rstrip("/").split("/")[-1] or path
        if name.endswith(".git"):
            name = name[:-4]
        return str(name)

    if target_type == "local_code":
        path_str = str(details.get("target_path", original) or original)
        try:
            return str(Path(path_str).name or path_str)
        except Exception:
            return str(path_str)

    if target_type == "ip_address":
        ip_value = str(details.get("target_ip", original) or original)
        return ip_value or original or "pentest"

    return str(original or "pentest")


def generate_run_name(targets_info: list[dict[str, Any]] | None = None) -> str:
    base_label = _derive_target_label_for_run_name(targets_info)
    slug = _slugify_for_run_name(base_label)

    random_suffix = secrets.token_hex(2)

    return f"{slug}_{random_suffix}"


def validate_run_name(value: str) -> str:
    if ".." in value or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", value):
        raise argparse.ArgumentTypeError("run name must be a safe 1-128 character identifier")
    # Reject names that start with a dot to prevent confusion with hidden
    # directories (e.g. .git, .ssh) in the runs folder. The regex above already
    # requires the first character to be alphanumeric, so this is a belt-and-
    # suspenders guard for clarity.
    if value.startswith("."):
        raise argparse.ArgumentTypeError("run name must not start with a dot")
    return value


def check_docker_connection() -> Any:
    try:
        return docker.from_env()
    except DockerException:
        console = Console()
        error_text = Text()
        error_text.append("DOCKER NOT AVAILABLE", style="bold red")
        error_text.append("\n\n", style="white")
        error_text.append("Cannot connect to Docker daemon.\n", style="white")
        error_text.append(
            "Please ensure Docker Desktop is installed and running, and try running "
            "lyrashield again.\n",
            style="white",
        )

        panel = Panel(
            error_text,
            title="[bold white]LYRASHIELD",
            title_align="left",
            border_style="red",
            padding=(1, 2),
        )
        console.print("\n", panel, "\n")
        raise RuntimeError("Docker not available") from None


def image_exists(client: Any, image_name: str) -> bool:
    try:
        client.images.get(image_name)
    except ImageNotFound:
        return False
    else:
        return True


def update_layer_status(layers_info: dict[str, str], layer_id: str, layer_status: str) -> None:
    from lyrashield.interface.image_pull import update_layer_status as _update_layer_status

    _update_layer_status(layers_info, layer_id, layer_status)


def validate_config_file(config_path: str) -> Path:
    console = Console()
    path = Path(config_path)

    if not path.exists():
        console.print(f"[bold red]Error:[/] Config file not found: {config_path}")
        sys.exit(1)

    if path.suffix != ".json":
        console.print("[bold red]Error:[/] Config file must be a .json file")
        sys.exit(1)

    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        console.print(f"[bold red]Error:[/] Invalid JSON in config file: {e}")
        sys.exit(1)

    if not isinstance(data, dict):
        console.print("[bold red]Error:[/] Config file must contain a JSON object")
        sys.exit(1)
    data = _as_str_dict(data)

    if "env" not in data or not isinstance(data.get("env"), dict):
        console.print("[bold red]Error:[/] Config file must have an 'env' object")
        sys.exit(1)

    return path
