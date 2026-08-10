"""Parallel Search-backed web research tool for real-time OSINT."""

from __future__ import annotations

import json
import logging
import re
import uuid
from typing import TYPE_CHECKING, Any, Literal, cast
from urllib.parse import urlparse

from agents import RunContextWrapper, function_tool

from lyrashield.policy.loader import load_settings


if TYPE_CHECKING:
    from strix.report.state import ReportState


logger = logging.getLogger(__name__)

_ALLOWED_TOPICS = frozenset(
    {
        "cve",
        "version",
        "exploit",
        "advisory",
        "framework",
        "library",
        "public-endpoints",
        "osint",
    }
)

_DEFAULT_API_BASE = "https://api.parallel.ai/v1"

_STOP_WORDS = frozenset(
    {
        "a",
        "about",
        "and",
        "are",
        "as",
        "at",
        "be",
        "by",
        "find",
        "for",
        "from",
        "has",
        "have",
        "how",
        "in",
        "is",
        "it",
        "of",
        "on",
        "or",
        "that",
        "the",
        "to",
        "what",
        "when",
        "where",
        "which",
        "with",
    }
)

_TOPIC_OBJECTIVES: dict[str, str] = {
    "cve": "Find public CVEs and security advisories for",
    "version": "Find the latest stable version and release notes for",
    "exploit": "Find publicly known exploits, bypasses, and proof-of-concepts for",
    "advisory": "Find recent security advisories and documentation about",
    "framework": "Find official documentation and security guidance for",
    "library": "Find package information and security issues for",
    "public-endpoints": "Find publicly documented endpoints, APIs, and infrastructure for",
    "osint": "Find public open-source intelligence about",
}

_SENSITIVE_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "uuid",
        re.compile(
            r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
            re.IGNORECASE,
        ),
        "[UUID]",
    ),
    (
        "email",
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        "[EMAIL]",
    ),
    (
        "ipv4",
        re.compile(
            r"\b(?:25[0-5]|2[0-4]\d|1\d{1,2}|\d{1,2})\.(?:25[0-5]|2[0-4]\d|1\d{1,2}|\d{1,2})"
            r"\.(?:25[0-5]|2[0-4]\d|1\d{1,2}|\d{1,2})\.(?:25[0-5]|2[0-4]\d|1\d{1,2}|\d{1,2})\b"
        ),
        "[IP]",
    ),
    (
        "ipv6",
        re.compile(r"\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\b", re.IGNORECASE),
        "[IP]",
    ),
    (
        "bearer",
        re.compile(r"\bBearer\s+[A-Za-z0-9_\-]+\b", re.IGNORECASE),
        "[TOKEN]",
    ),
    (
        "api_key",
        re.compile(r"\b(?:api[_-]?key|apikey)\s*[:=]\s*[^\s\"'<>]+", re.IGNORECASE),
        "[SECRET]",
    ),
    (
        "password",
        re.compile(r"\b(?:password|passwd|pwd)\s*[:=]\s*[^\s\"'<>]+", re.IGNORECASE),
        "[SECRET]",
    ),
    (
        "secret",
        re.compile(r"\b(?:secret|token)\s*[:=]\s*[^\s\"'<>]+", re.IGNORECASE),
        "[SECRET]",
    ),
    (
        "long_hex",
        re.compile(r"\b[0-9a-f]{32,64}\b", re.IGNORECASE),
        "[SECRET]",
    ),
    (
        "long_random",
        re.compile(r"\b[A-Za-z0-9_\-]{40,}\b"),
        "[SECRET]",
    ),
]

_URL_PATTERN = re.compile(r"https?://\S+")


def _redact_query(query: str, topic: str, target_hosts: set[str] | None) -> str:
    """Redact credentials, PII, and sensitive tokens from a search query."""
    redacted = query
    for _name, pattern, replacement in _SENSITIVE_PATTERNS:
        redacted = pattern.sub(replacement, redacted)

    redacted = _URL_PATTERN.sub("[URL]", redacted)

    if target_hosts and topic != "public-endpoints":
        for host in sorted(target_hosts, key=len, reverse=True):
            redacted = re.sub(
                rf"\b{re.escape(host)}\b",
                "[TARGET]",
                redacted,
                flags=re.IGNORECASE,
            )

    return redacted.strip()


def _query_to_keywords(query: str, topic: str, keywords: list[str] | None) -> list[str]:
    """Build 2-3 short keyword phrases for Parallel Search."""
    if keywords:
        cleaned = [k.strip() for k in keywords if k.strip()]
        if cleaned:
            return cleaned[:3]

    words = [
        w for w in re.split(r"\W+", query.lower()) if w and len(w) > 2 and w not in _STOP_WORDS
    ]
    if not words:
        return [query.strip()]

    q1 = " ".join(words[:6])
    q2_words = [*words[:3], topic][:6]
    q2 = " ".join(q2_words)
    if q1 == q2:
        return [q1]
    return [q1, q2]


def _build_objective(topic: str, query: str) -> str:
    """Build a generic, sanitized objective for Parallel Search."""
    prefix = _TOPIC_OBJECTIVES.get(topic, "Find public information about")
    return f"{prefix} {query}"


def _estimate_cost(mode: str, settings: Any) -> float:
    """Return the per-call cost reserve for the requested search mode."""
    if mode == "turbo":
        return float(settings.turbo_cost_per_call)
    if mode == "basic":
        return float(settings.basic_cost_per_call)
    if mode == "advanced":
        return float(settings.advanced_cost_per_call)
    return float(settings.turbo_cost_per_call)


def _target_hosts_from_report() -> set[str] | None:
    """Extract target hostnames from the global report state, if any."""
    from strix.report.state import get_global_report_state

    report_state = get_global_report_state()
    if report_state is None:
        return None

    targets_info = report_state.run_record.get("targets_info", [])
    if not isinstance(targets_info, list):
        return None

    hosts: set[str] = set()
    for item in targets_info:
        if isinstance(item, str):
            host = urlparse(item).hostname or item
            hosts.add(host)
            hosts.add(item)
        elif isinstance(item, dict):
            for key in ("target", "host", "url", "uri"):
                value = item.get(key)
                if isinstance(value, str):
                    host = urlparse(value).hostname or value
                    hosts.add(host)
                    hosts.add(value)
    return hosts


def _validate_web_search_call(
    web_search_settings: Any,
    topic: str,
    report_state: ReportState | None,
) -> str | None:
    """Return an error message if the call should not proceed, or None."""
    if not web_search_settings.enabled:
        return "Web search is disabled. Set LYRASHIELD_WEB_SEARCH_ENABLED=1 to enable."
    if not web_search_settings.api_key:
        return (
            "Web search is not configured. Set LYRASHIELD_WEB_SEARCH_API_KEY or PARALLEL_API_KEY."
        )
    if topic not in _ALLOWED_TOPICS:
        return f"Invalid topic '{topic}'. Allowed: {sorted(_ALLOWED_TOPICS)}"
    if report_state is None:
        return None
    call_count, total_cost = report_state.get_web_search_stats()
    max_calls = web_search_settings.max_calls_per_scan
    if max_calls > 0 and call_count >= max_calls:
        return f"Web search call limit reached ({call_count}/{max_calls})."
    budget = web_search_settings.budget_usd
    if budget > 0 and total_cost >= budget:
        return f"Web search budget exceeded (${total_cost:.4f}/${budget:.2f})."
    return None


def _summarize_results(results: list[dict[str, Any]], max_results: int) -> str:
    """Format search results into a concise, citation-ready summary."""
    if not results:
        return "No results found."

    lines: list[str] = []
    for idx, result in enumerate(results[:max_results], start=1):
        title = result.get("title") or "Untitled result"
        url = result.get("url") or ""
        excerpts = result.get("excerpts")
        excerpt = ""
        if isinstance(excerpts, list) and excerpts:
            excerpt = str(excerpts[0]).strip()
        elif isinstance(excerpts, str):
            excerpt = excerpts.strip()

        if url:
            lines.append(f"{idx}. [{title}]({url})")
        else:
            lines.append(f"{idx}. {title}")
        if excerpt:
            lines.append(f"   {excerpt[:300].strip()}")

    return "\n".join(lines)


@function_tool(timeout=15)
async def web_search(
    ctx: RunContextWrapper,
    query: str,
    topic: Literal[
        "cve",
        "version",
        "exploit",
        "advisory",
        "framework",
        "library",
        "public-endpoints",
        "osint",
    ] = "advisory",
    mode: Literal["turbo", "basic", "advanced"] = "turbo",
    keywords: list[str] | None = None,
) -> str:
    """Search the live web for public security information via Parallel Search.

    Use this when the task needs a fact that may be newer than the model's
    training data, such as CVEs, library versions, public exploits, or
    real-world bypasses. Keep ``query`` generic and avoid including internal
    hostnames, tokens, or credentials; the tool will redact obvious sensitive
    patterns before sending anything to Parallel.
    """
    del ctx

    settings = load_settings()
    web_search_settings = settings.web_search
    api_key = web_search_settings.api_key

    from lyrashield.lifecycle.hooks import get_active_hooks
    from strix.report.state import get_global_report_state

    report_state = get_global_report_state()

    error = _validate_web_search_call(web_search_settings, topic, report_state)
    if error:
        return json.dumps(
            {"success": False, "message": error},
            ensure_ascii=False,
            default=str,
        )

    api_key = cast("str", web_search_settings.api_key)
    target_hosts = _target_hosts_from_report()
    redacted_query = _redact_query(query, topic, target_hosts)

    estimated_cost = _estimate_cost(mode, web_search_settings)
    reservation_key = f"web_search:{uuid.uuid4().hex}"

    hooks = get_active_hooks()
    try:
        if hooks is not None:
            await hooks.reserve_web_search_call(
                key=reservation_key,
                estimated_cost=estimated_cost,
            )

        search_queries = _query_to_keywords(redacted_query, topic, keywords)
        objective = _build_objective(topic, redacted_query)

        api_base = (web_search_settings.api_base or _DEFAULT_API_BASE).rstrip("/")
        import httpx

        async with httpx.AsyncClient(timeout=15) as client:
            response = await client.post(
                f"{api_base}/search",
                headers={
                    "Content-Type": "application/json",
                    "x-api-key": api_key,
                },
                json={
                    "mode": mode,
                    "objective": objective,
                    "search_queries": search_queries,
                    "max_chars_total": web_search_settings.max_chars_total,
                    "advanced_settings": {
                        "max_results": web_search_settings.max_results,
                    },
                },
            )
            response.raise_for_status()
            payload = response.json()

        results = payload.get("results", [])
        if not isinstance(results, list):
            results = []

        content = _summarize_results(results, web_search_settings.max_results)

        result: dict[str, Any] = {
            "success": True,
            "content": content,
            "query": redacted_query,
            "mode": mode,
            "results": results[: web_search_settings.max_results],
        }

        if report_state is not None:
            report_state.record_web_search_cost(
                estimated_cost,
                query=redacted_query,
                mode=mode,
            )

        if hooks is not None:
            await hooks.release_web_search_call(
                key=reservation_key,
                actual_cost=estimated_cost,
            )

        return json.dumps(result, ensure_ascii=False, default=str)

    except httpx.HTTPError as exc:
        logger.exception("Parallel Search request failed")
        if hooks is not None:
            await hooks.release_web_search_call(
                key=reservation_key,
                actual_cost=0.0,
            )
        return json.dumps(
            {"success": False, "message": f"Parallel Search failed: {exc}"},
            ensure_ascii=False,
            default=str,
        )
    except Exception as exc:
        logger.exception("web_search tool failed")
        if hooks is not None:
            await hooks.release_web_search_call(
                key=reservation_key,
                actual_cost=0.0,
            )
        return json.dumps(
            {"success": False, "message": f"Web search failed: {exc}"},
            ensure_ascii=False,
            default=str,
        )
