"""Cross-cutting text redaction for secrets, PII, and internal paths.

Used by web-search query sanitization, customer-facing report DLP, and
conversation compaction so sensitive values and internal filesystem paths never
cross the trust boundary.
"""

from __future__ import annotations

import re


_SECRET_PLACEHOLDER = "[SECRET]"  # noqa: S105  # nosec B105
_PII_PLACEHOLDER = "[PII]"
_TOKEN_PLACEHOLDER = "[TOKEN]"  # noqa: S105  # nosec B105
_JWT_PLACEHOLDER = "[JWT]"
_AWS_KEY_PLACEHOLDER = "[AWS_KEY]"
_PRIVATE_KEY_PLACEHOLDER = "[PRIVATE_KEY]"
_INTERNAL_PATH_PLACEHOLDER = "[INTERNAL_PATH]"
_SPILL_PATH_PLACEHOLDER = "[SPILL_PATH]"

# Ordered from most specific (private keys, JWTs, AWS keys) to broad
# high-entropy fallbacks, so precise patterns win before generic ones.
_SENSITIVE_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "private_key",
        re.compile(
            r"-----BEGIN (?:OPENSSH |RSA |DSA |EC |PGP |ED25519 )?PRIVATE KEY-----"
            r".*?"
            r"-----END (?:OPENSSH |RSA |DSA |EC |PGP |ED25519 )?PRIVATE KEY-----",
            re.DOTALL,
        ),
        _PRIVATE_KEY_PLACEHOLDER,
    ),
    (
        "jwt",
        re.compile(r"eyJ[A-Za-z0-9_-]*(?:\.[A-Za-z0-9_-]*){2}"),
        _JWT_PLACEHOLDER,
    ),
    (
        "aws_access_key",
        re.compile(r"\b(?:AKIA|ASIA|AROA|AIDA)[A-Z0-9]{16}\b"),
        _AWS_KEY_PLACEHOLDER,
    ),
    (
        "uuid",
        re.compile(
            r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
            re.IGNORECASE,
        ),
        _PII_PLACEHOLDER,
    ),
    (
        "email",
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        _PII_PLACEHOLDER,
    ),
    (
        "ipv4",
        re.compile(
            r"\b(?:25[0-5]|2[0-4]\d|1\d{1,2}|\d{1,2})"
            r"\.(?:25[0-5]|2[0-4]\d|1\d{1,2}|\d{1,2})"
            r"\.(?:25[0-5]|2[0-4]\d|1\d{1,2}|\d{1,2})"
            r"\.(?:25[0-5]|2[0-4]\d|1\d{1,2}|\d{1,2})\b"
        ),
        _PII_PLACEHOLDER,
    ),
    (
        "ipv6",
        re.compile(r"\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\b", re.IGNORECASE),
        _PII_PLACEHOLDER,
    ),
    (
        "bearer",
        re.compile(r"\bBearer\s+[A-Za-z0-9_\-]+\b", re.IGNORECASE),
        _TOKEN_PLACEHOLDER,
    ),
    (
        "api_key",
        re.compile(
            r"\b(?:api[_-]?key|apikey)\s*[:=]\s*[^\s\"'<>]+",
            re.IGNORECASE,
        ),
        _SECRET_PLACEHOLDER,
    ),
    (
        "password",
        re.compile(
            r"\b(?:password|passwd|pwd)\s*[:=]\s*[^\s\"'<>]+",
            re.IGNORECASE,
        ),
        _SECRET_PLACEHOLDER,
    ),
    (
        "secret_or_token",
        re.compile(
            r"\b(?:secret|token)\s*[:=]\s*[^\s\"'<>]+",
            re.IGNORECASE,
        ),
        _SECRET_PLACEHOLDER,
    ),
]

# Paths that should NEVER appear in customer-facing output, regardless of scan mode.
_ALWAYS_REDACT_PATH_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "strix_spill_path",
        re.compile(r"/workspace/\.strix/tool-output/[^\s\"'<>]+"),
        _SPILL_PATH_PLACEHOLDER,
    ),
    (
        "strix_tmp_state",
        re.compile(r"/tmp/\.strix[^\s\"'<>]*"),  # noqa: S108  # nosec B108
        _INTERNAL_PATH_PLACEHOLDER,
    ),
]

# General workspace paths that are redacted in blackbox mode but preserved in
# whitebox mode (where /workspace/<subdir> is the target codebase).
_MODE_DEPENDENT_PATH_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "workspace_path",
        re.compile(r"/workspace(?:/[^\s\"'<>]*)?"),
        _INTERNAL_PATH_PLACEHOLDER,
    ),
]


def redact_secrets(text: str) -> str:
    """Redact credentials, PII, and high-entropy tokens from ``text``."""
    redacted = text
    for _name, pattern, replacement in _SENSITIVE_PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    return redacted


def redact_internal_paths(text: str) -> str:
    """Redact internal sandbox filesystem paths from ``text``.

    Always redacts spill paths and tmp state. Also redacts general
    ``/workspace/`` paths — use :func:`redact_text` with
    ``include_internal_paths=False`` to preserve target workspace paths
    in whitebox mode.
    """
    redacted = text
    for _name, pattern, replacement in _ALWAYS_REDACT_PATH_PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    for _name, pattern, replacement in _MODE_DEPENDENT_PATH_PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    return redacted


def redact_spill_paths(text: str) -> str:
    """Redact only spill paths and tmp state, preserving general workspace paths."""
    redacted = text
    for _name, pattern, replacement in _ALWAYS_REDACT_PATH_PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    return redacted


def redact_text(text: str, *, include_internal_paths: bool = True) -> str:
    """Redact secrets and, by default, internal paths from ``text``.

    Returns a copy of ``text`` with sensitive values replaced by clearly
    labelled placeholders. The original string is never modified.

    When ``include_internal_paths=False`` (whitebox mode), spill paths and
    tmp state are still redacted, but general ``/workspace/`` target paths
    are preserved so findings reference the actual codebase.
    """
    redacted = redact_secrets(text)
    if include_internal_paths:
        redacted = redact_internal_paths(redacted)
    else:
        redacted = redact_spill_paths(redacted)
    return redacted
