"""Cross-cutting text redaction for secrets, PII, and internal paths.

Used by web-search query sanitization, customer-facing report DLP, and
conversation compaction so sensitive values and internal filesystem paths never
cross the trust boundary.
"""

from __future__ import annotations

import re
from urllib.parse import unquote, urlparse, urlunparse


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
#
# The list is split into two groups for the redaction fast-path:
#   * ``_ALWAYS_RUN_PATTERNS`` — uuid / ipv4 / ipv6 — have no keyword trigger
#     in the fast-path marker set, so they must run unconditionally to avoid
#     leaking PII (e.g. ``"Connected to 10.0.5.23"`` with no secret keyword).
#   * ``_KEYWORD_GATED_PATTERNS`` — the expensive keyword-anchored patterns
#     (password, secret, token, bearer, email, …) that are only applied when
#     a cheap substring pre-check confirms a potential match.
_ALWAYS_RUN_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "uuid",
        re.compile(
            r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
            re.IGNORECASE,
        ),
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
        # Matches both full (8-group) and RFC 4291 compressed forms (``::``).
        # The previous pattern ``(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}`` only
        # matched uncompressed addresses and missed ``::1`` / ``2001:db8::1``,
        # leaking loopback and compressed IPv6 PII into logs.  Boundaries use
        # ``(?<![\w:])`` / ``(?![\w:])`` instead of ``\b`` because ``::1``
        # starts with a non-word char (``:``), so ``\b`` would not fire.
        re.compile(
            r"(?<![\w:])"
            r"(?:"
            r"(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}"  # full 8 groups
            r"|(?:[0-9a-f]{1,4}:){1,7}:"  # 1:: ... 1:2:3:4:5:6:7::
            r"|(?:[0-9a-f]{1,4}:){1,6}(?::[0-9a-f]{1,4})"  # 1::8 ... 1:2:3:4:5:6::8
            r"|(?:[0-9a-f]{1,4}:){1,5}(?::[0-9a-f]{1,4}){1,2}"
            r"|(?:[0-9a-f]{1,4}:){1,4}(?::[0-9a-f]{1,4}){1,3}"
            r"|(?:[0-9a-f]{1,4}:){1,3}(?::[0-9a-f]{1,4}){1,4}"
            r"|(?:[0-9a-f]{1,4}:){1,2}(?::[0-9a-f]{1,4}){1,5}"
            r"|[0-9a-f]{1,4}:(?::[0-9a-f]{1,4}){1,6}"
            r"|:(?::[0-9a-f]{1,4}){1,7}"
            r"|::"
            r")"
            r"(?![\w:])",
            re.IGNORECASE,
        ),
        _PII_PLACEHOLDER,
    ),
]

_KEYWORD_GATED_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
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
        "email",
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
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

# Combined list preserved for backward compatibility with any external callers
# that iterate over the full ordered set.
_SENSITIVE_PATTERNS = _ALWAYS_RUN_PATTERNS + _KEYWORD_GATED_PATTERNS

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
    # Host-side home directories never belong in durable/public artifacts:
    # they identify the operator's machine. Sandbox-internal /workspace paths
    # are handled separately by the mode-dependent patterns.
    (
        "host_home_path",
        re.compile(r"(?:/Users|/home)/[^\s\"'<>]+"),
        _INTERNAL_PATH_PLACEHOLDER,
    ),
    (
        "host_home_short",
        re.compile(r"~/[^\s\"'<>]+"),
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


# Fast-path: cheap substring checks that cover the keyword-anchored patterns.
# If none of these appear, the text cannot match any keyword-gated regex and we
# skip that (expensive) suite — important for large shell outputs on every
# exec_command.  The uuid/ipv4/ipv6 patterns have no keyword trigger, so they
# are applied unconditionally (see ``_ALWAYS_RUN_PATTERNS``).
_SECRET_FAST_PATH_MARKERS = (
    "private key",
    "eyj",
    "akia",
    "asia",
    "aroa",
    "aida",
    "api_key",
    "apikey",
    "api-key",
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "bearer",
    "@",
)


def redact_secrets(text: str) -> str:
    """Redact credentials, PII, and high-entropy tokens from ``text``.

    The uuid, ipv4, and ipv6 patterns are applied unconditionally because they
    have no keyword trigger in the fast-path marker set — without this, text
    such as ``"Connected to 10.0.5.23"`` would pass through unredacted.  The
    remaining keyword-anchored patterns (password, secret, token, bearer,
    email, …) are gated behind a cheap substring pre-check for performance.
    """
    if not text:
        return text
    # Always run the cheap uuid/IP patterns — they have no keyword trigger.
    redacted = text
    for _name, pattern, replacement in _ALWAYS_RUN_PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    # Fast-path: only run the expensive keyword-anchored patterns when a
    # potential marker is present.
    text_lower = redacted.lower()
    if any(marker in text_lower for marker in _SECRET_FAST_PATH_MARKERS):
        for _name, pattern, replacement in _KEYWORD_GATED_PATTERNS:
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

    When ``include_internal_paths=False`` (whitebox mode), spill paths, tmp
    state, and host home directories are still redacted, but general
    ``/workspace/`` target paths are preserved so findings reference the
    actual codebase.
    """
    redacted = redact_secrets(text)
    if include_internal_paths:
        redacted = redact_internal_paths(redacted)
    else:
        redacted = redact_spill_paths(redacted)
    return redacted


# URL userinfo (``scheme://user:password@host``) is removed wholesale: the
# credential is secret and the username can identify the operator.
_URL_USERINFO_RE = re.compile(r"([a-z][a-z0-9+.-]*://)([^/@:\s]+):([^@\s/]+)@", re.IGNORECASE)

# Query parameters whose VALUES are redacted even when the key itself is not
# secret-looking. Values are replaced, keys preserved, so the URL shape stays
# useful for reproducing a request.
_SENSITIVE_QUERY_KEYS = (
    "token",
    "access_token",
    "id_token",
    "refresh_token",
    "api_key",
    "apikey",
    "key",
    "secret",
    "client_secret",
    "password",
    "passwd",
    "signature",
    "sig",
    "session",
    "sessionid",
    "auth",
    "authorization",
    "credential",
    "code",
)


def redact_url(url: str) -> str:
    """Redact URL credentials and sensitive query values, keeping the shape.

    Userinfo is replaced with ``[REDACTED]@`` and values of sensitive query
    parameters are replaced with ``[REDACTED]``; scheme, host, port, path, and
    non-sensitive parameters survive so the URL remains a usable target
    identifier.

    Uses ``urllib.parse`` for robust parsing that handles case-insensitive
    query keys, URL-encoded key variants, and edge cases the regex approach
    missed. Falls back to manual parsing when ``urlparse`` rejects the URL
    (e.g. when a prior redaction pass left ``[PLACEHOLDER]`` in the netloc,
    which urlparse interprets as an invalid IPv6 literal).
    """
    if not url:
        return url
    # Strip userinfo first using a simple scan — robust against placeholders
    # that urlparse would reject as invalid IPv6 literals.
    redacted = _URL_USERINFO_RE.sub(r"\1[REDACTED]@", url)
    # Now parse for query redaction. urlparse may still fail on edge cases;
    # fall back to manual query splitting.
    try:
        parsed = urlparse(redacted)
        query = parsed.query
        fragment = parsed.fragment
        base = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, "", ""))
    except ValueError:
        # urlparse failed (e.g. bracketed placeholder in netloc); split
        # query/fragment manually.
        if "?" not in redacted:
            return redacted
        base, _, rest = redacted.partition("?")
        query, _, fragment = rest.partition("#")
        fragment = f"#{fragment}" if fragment else ""
    # Redact sensitive query parameter values (case-insensitive, decoded).
    if not query:
        return base + (f"#{fragment}" if fragment and not base.endswith("#") else "")
    pairs = query.split("&")
    kept: list[str] = []
    for pair in pairs:
        key, sep, value = pair.partition("=")
        decoded_key = unquote(key).strip().lower()
        if decoded_key in _SENSITIVE_QUERY_KEYS and value:
            kept.append(f"{key}{sep}[REDACTED]")
        else:
            kept.append(pair)
    result = f"{base}?{'&'.join(kept)}"
    if fragment and not result.endswith(fragment):
        result += fragment
    return result
