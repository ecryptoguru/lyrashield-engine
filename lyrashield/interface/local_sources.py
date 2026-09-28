"""Offline target classification and local-source preparation helpers."""

from __future__ import annotations

import ipaddress
import logging
import os
import re
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlparse


logger = logging.getLogger("lyrashield.interface.utils")


def _as_str_dict(value: Any) -> dict[str, Any]:
    return cast("dict[str, Any]", value) if isinstance(value, dict) else {}


def _as_str_or_none(value: Any) -> str | None:
    return value if isinstance(value, str) else None


_WILDCARD_IPV4_HOST = str(ipaddress.IPv4Address(0))


def infer_target_type(target: str) -> tuple[str, dict[str, str]]:
    if not target:
        raise ValueError("Target must be a non-empty string")

    target = target.strip()

    if target.startswith("git@"):
        return "repository", {"target_repo": target}

    if target.startswith("git://"):
        return "repository", {"target_repo": target}

    parsed = urlparse(target)
    if parsed.scheme in ("http", "https"):
        # Inference is offline-only: the engine never resolves DNS or sends HTTP
        # requests to the target while classifying it. Credential-bearing URLs
        # and ``.git`` remotes are still recognized as repositories, but an
        # ambiguous non-suffixed HTTP(S) URL defaults to a web target — use
        # ``--target-type repository`` for a bare HTTP(S) Git remote.
        if parsed.username or parsed.password:
            return "repository", {"target_repo": target}
        if parsed.path.rstrip("/").endswith(".git"):
            return "repository", {"target_repo": target}
        return "web_application", {"target_url": target}

    try:
        ip_obj = ipaddress.ip_address(target)
    except ValueError:
        pass
    else:
        return "ip_address", {"target_ip": str(ip_obj)}

    path = Path(target).expanduser()
    try:
        if path.exists():
            if path.is_dir():
                return "local_code", {"target_path": str(path.resolve())}
            raise ValueError(f"Path exists but is not a directory: {target}")
    except (OSError, RuntimeError) as e:
        raise ValueError(f"Invalid path: {target} - {e!s}") from e

    if target.endswith(".git"):
        return "repository", {"target_repo": target}

    if "/" in target:
        host_part, _, path_part = target.partition("/")
        if "." in host_part and not host_part.startswith(".") and path_part:
            # Bare host/path (e.g. github.com/org/repo) is ambiguous; offline
            # inference treats it as a web target rather than probing it.
            return "web_application", {"target_url": f"https://{target}"}

    if "." in target and "/" not in target and not target.startswith("."):
        parts = target.split(".")
        if len(parts) >= 2 and all(p and p.strip() for p in parts):
            return "web_application", {"target_url": f"https://{target}"}

    raise ValueError(
        f"Invalid target: {target}\n"
        "Target must be one of:\n"
        "- A valid URL (http:// or https://)\n"
        "- A Git repository URL (https://host/org/repo or git@host:org/repo.git)\n"
        "- A local directory path\n"
        "- A domain name (e.g., example.com)\n"
        "- An IP address (e.g., 192.168.1.10)"
    )


TARGET_TYPE_CHOICES: tuple[str, ...] = (
    "repository",
    "web_application",
    "local_code",
    "ip_address",
)


def _explicit_repository_ref(target: str) -> str:
    """Return the normalized Git remote for a ``--target-type repository`` input."""
    if target.startswith(("git@", "git://")):
        return target
    parsed = urlparse(target)
    if parsed.scheme in ("http", "https"):
        if not parsed.netloc:
            raise ValueError(
                f"--target-type repository requires a usable Git remote; '{target}' has no host."
            )
        return target
    if parsed.scheme:
        raise ValueError(
            f"--target-type repository does not accept '{parsed.scheme}:' remotes. "
            "Use an https://, git@host:path, or git:// remote."
        )
    path = Path(target).expanduser()
    try:
        exists = path.exists()
    except (OSError, RuntimeError) as e:
        raise ValueError(f"Invalid target '{target}': {e!s}") from e
    if exists:
        raise ValueError(
            f"--target-type repository requires a remote Git URL; '{target}' is a local "
            "path. Use --target-type local_code or omit --target-type."
        )
    if "/" in target:
        host_part, _, path_part = target.partition("/")
        if "." in host_part and not host_part.startswith(".") and path_part:
            return f"https://{target}"
    raise ValueError(
        "--target-type repository requires a Git remote "
        "(https://host/org/repo[.git], git@host:org/repo, or git://host/org/repo); "
        f"'{target}' is not one. Omit --target-type to classify the input automatically."
    )


def _explicit_web_url(target: str) -> str:
    """Return the normalized URL for a ``--target-type web_application`` input."""
    if target.startswith(("git@", "git://")):
        raise ValueError(
            f"--target-type web_application given a Git remote '{target}'. "
            "Use --target-type repository or omit --target-type."
        )
    parsed = urlparse(target)
    if parsed.scheme in ("http", "https"):
        if not parsed.netloc:
            raise ValueError(
                f"--target-type web_application requires a usable URL; '{target}' has no host."
            )
        if parsed.username or parsed.password:
            raise ValueError(
                "--target-type web_application does not accept credentials embedded in "
                f"'{target}'. Remove the credentials from the URL, or use "
                "--target-type repository for a credential-bearing Git remote."
            )
        if parsed.path.rstrip("/").endswith(".git"):
            raise ValueError(
                f"--target-type web_application given '{target}', which ends with '.git' — "
                "a Git remote. Use --target-type repository or omit --target-type."
            )
        return target
    if parsed.scheme:
        raise ValueError(
            "--target-type web_application accepts http(s) URLs or domain names only; "
            f"'{parsed.scheme}:' is not supported."
        )
    try:
        ipaddress.ip_address(target)
    except ValueError:
        pass
    else:
        raise ValueError(
            f"--target-type web_application given IP address '{target}'. "
            "Use --target-type ip_address or prefix it with http(s)://."
        )
    path = Path(target).expanduser()
    try:
        exists = path.exists()
    except (OSError, RuntimeError) as e:
        raise ValueError(f"Invalid target '{target}': {e!s}") from e
    if exists:
        raise ValueError(
            f"--target-type web_application given local path '{target}'. "
            "Use --target-type local_code or omit --target-type."
        )
    if target.endswith(".git"):
        raise ValueError(
            f"--target-type web_application given '{target}', which ends with '.git' — "
            "a Git remote. Use --target-type repository or omit --target-type."
        )
    if "/" in target:
        host_part, _, path_part = target.partition("/")
        if "." in host_part and not host_part.startswith(".") and path_part:
            return f"https://{target}"
    if "." in target and not target.startswith("."):
        parts = target.split(".")
        if len(parts) >= 2 and all(p and p.strip() for p in parts):
            return f"https://{target}"
    raise ValueError(
        f"--target-type web_application requires an http(s) URL or a domain name; "
        f"'{target}' is not one."
    )


def _explicit_local_path(target: str) -> str:
    """Return the resolved directory for a ``--target-type local_code`` input."""
    parsed = urlparse(target)
    if parsed.scheme in ("http", "https") or target.startswith(("git@", "git://")):
        raise ValueError(
            f"--target-type local_code requires a local directory; '{target}' is a remote "
            "target. Use --target-type repository or --target-type web_application, or "
            "omit --target-type."
        )
    path = Path(target).expanduser()
    try:
        if path.exists():
            if path.is_dir():
                return str(path.resolve())
            raise ValueError(f"Path exists but is not a directory: {target}")
    except (OSError, RuntimeError) as e:
        raise ValueError(f"Invalid path: {target} - {e!s}") from e
    raise ValueError(
        f"--target-type local_code requires an existing local directory; '{target}' does "
        "not exist. For a remote Git repository use --target-type repository."
    )


def _explicit_ip(target: str) -> str:
    """Return the normalized address for a ``--target-type ip_address`` input."""
    try:
        ip_obj = ipaddress.ip_address(target)
    except ValueError:
        raise ValueError(
            f"--target-type ip_address requires an IPv4 or IPv6 address; '{target}' is "
            "not one. For a host URL use --target-type web_application."
        ) from None
    return str(ip_obj)


def resolve_target_type(
    target: str, explicit_kind: str | None = None
) -> tuple[str, dict[str, str]]:
    """Classify *target*, honoring an operator-supplied *explicit_kind* when given.

    Both modes are offline-only: classification never resolves DNS and never
    sends HTTP requests to the target. An explicit kind validates the input's
    shape instead of probing it — catching a wrong-kind flag early — but it is
    not authorization: URL credential, source-path, and target-authorization
    checks still apply downstream.
    """
    if explicit_kind is None:
        return infer_target_type(target)
    if explicit_kind not in TARGET_TYPE_CHOICES:
        raise ValueError(
            f"Unknown --target-type '{explicit_kind}'. "
            f"Valid kinds: {', '.join(TARGET_TYPE_CHOICES)}."
        )
    if not target:
        raise ValueError("Target must be a non-empty string")
    target = target.strip()
    if not target:
        raise ValueError("Target must be a non-empty string")
    if explicit_kind == "repository":
        return "repository", {"target_repo": _explicit_repository_ref(target)}
    if explicit_kind == "web_application":
        return "web_application", {"target_url": _explicit_web_url(target)}
    if explicit_kind == "local_code":
        return "local_code", {"target_path": _explicit_local_path(target)}
    return "ip_address", {"target_ip": _explicit_ip(target)}


def read_target_list_file(path_str: str) -> list[str]:
    """Read scan targets from a file, one target per non-empty, non-comment line."""
    if not path_str or not path_str.strip():
        raise ValueError("--target-list path must not be empty.")

    path = Path(path_str).expanduser()
    if not path.is_file():
        raise ValueError(f"Target list file '{path_str}' is not an existing file.")

    try:
        targets = [
            target
            for line in path.read_text(encoding="utf-8").splitlines()
            if (target := line.strip()) and not target.startswith("#")
        ]
    except UnicodeDecodeError as e:
        raise ValueError(f"Target list file '{path_str}' must be valid UTF-8 text: {e!s}") from e
    except OSError as e:
        raise ValueError(f"Failed to read target list file '{path_str}': {e!s}") from e

    targets = [target for target in targets if target]
    if not targets:
        raise ValueError(f"Target list file '{path_str}' is empty.")
    return targets


def sanitize_name(name: str) -> str:
    sanitized = re.sub(r"[^A-Za-z0-9._-]", "-", name.strip())
    if not sanitized or sanitized in {".", ".."}:
        return "target"
    return sanitized


def derive_repo_base_name(repo_url: str) -> str:
    if repo_url.endswith("/"):
        repo_url = repo_url[:-1]

    if ":" in repo_url and repo_url.startswith("git@"):
        path_part = repo_url.split(":", 1)[1]
    else:
        path_part = urlparse(repo_url).path or repo_url

    candidate = path_part.split("/")[-1]
    if candidate.endswith(".git"):
        candidate = candidate[:-4]

    return sanitize_name(candidate or "repository")


def derive_local_base_name(path_str: str) -> str:
    try:
        base = Path(path_str).resolve().name
    except (OSError, RuntimeError):
        base = Path(path_str).name
    return sanitize_name(base or "workspace")


def assign_workspace_subdirs(targets_info: list[dict[str, Any]]) -> None:
    name_counts: dict[str, int] = {}

    for target in targets_info:
        target_type = str(target.get("type") or "")
        details = _as_str_dict(target.get("details"))

        base_name: str | None = None
        if target_type == "repository":
            base_name = derive_repo_base_name(str(details.get("target_repo") or ""))
        elif target_type == "local_code":
            base_name = derive_local_base_name(str(details.get("target_path") or "local"))

        if base_name is None:
            continue

        count = name_counts.get(base_name, 0) + 1
        name_counts[base_name] = count

        workspace_subdir = base_name if count == 1 else f"{base_name}-{count}"

        details["workspace_subdir"] = workspace_subdir


def is_whitebox_scan(targets_info: list[dict[str, Any]]) -> bool:
    """True iff any target is a local source tree (whitebox / source-aware)."""
    return any(t.get("type") == "local_code" for t in targets_info or [])


def collect_local_sources(
    targets_info: list[dict[str, Any]],
    *,
    mount_cloned_repositories: bool = False,
) -> list[dict[str, Any]]:
    local_sources: list[dict[str, Any]] = []

    for target_info in targets_info:
        details = _as_str_dict(target_info.get("details"))
        workspace_subdir = _as_str_or_none(details.get("workspace_subdir"))

        if target_info.get("type") == "local_code" and "target_path" in details:
            local_sources.append(
                {
                    "source_path": str(details["target_path"]),
                    "workspace_subdir": workspace_subdir,
                    "mount": bool(details.get("mount", False)),
                }
            )

        elif target_info.get("type") == "repository" and "cloned_repo_path" in details:
            local_sources.append(
                {
                    "source_path": str(details["cloned_repo_path"]),
                    "workspace_subdir": workspace_subdir,
                    "mount": mount_cloned_repositories,
                }
            )

    return local_sources


def directory_size_bytes(path: Path) -> int:
    """Total size in bytes of regular files under ``path`` (symlinks not followed).

    Best-effort: files that disappear or can't be stat'd mid-walk are skipped.
    Used as a cheap (stat-only) pre-flight to estimate the cost of streaming a
    local target into the sandbox before we actually try to copy it.

    Directories that can't be listed (e.g. permission denied) are logged and
    skipped rather than silently dropped — so an under-count is at least
    visible — but the returned total then excludes their contents.
    """

    def _on_walk_error(error: OSError) -> None:
        logger.warning("Could not read %s while measuring size: %s", error.filename, error)

    total = 0
    for root, _dirs, files in os.walk(path, followlinks=False, onerror=_on_walk_error):
        for name in files:
            file_path = os.path.join(root, name)  # noqa: PTH118
            try:
                if os.path.islink(file_path):  # noqa: PTH114
                    continue
                total += os.path.getsize(file_path)  # noqa: PTH202
            except OSError:
                continue
    return total


def find_oversized_local_targets(
    targets_info: list[dict[str, Any]], max_bytes: int
) -> list[tuple[str, int]]:
    """Return ``(path, size_bytes)`` for non-mounted local targets over ``max_bytes``.

    Mounted targets are bind-mounted rather than copied, so their size is
    irrelevant and they are excluded. A ``max_bytes`` of zero or less disables
    the check entirely (returns no targets).
    """
    if max_bytes <= 0:
        return []
    oversized: list[tuple[str, int]] = []
    for target in targets_info:
        if target.get("type") != "local_code":
            continue
        details = _as_str_dict(target.get("details"))
        if details.get("mount"):
            continue
        target_path = str(details.get("target_path") or "")
        if not target_path:
            continue
        size = directory_size_bytes(Path(target_path))
        if size > max_bytes:
            oversized.append((target_path, size))
    return oversized


def build_mount_targets_info(mount_paths: list[str]) -> list[dict[str, Any]]:
    """Build ``targets_info`` entries for ``--mount`` directories.

    Each path must be an existing local directory; it is bind-mounted into the
    sandbox (read-only) instead of being copied file-by-file. Raises
    ``ValueError`` for an empty path, or one that does not exist or is not a
    directory.
    """
    targets_info: list[dict[str, Any]] = []
    for raw in mount_paths:
        if not raw or not raw.strip():
            raise ValueError("--mount path must not be empty.")
        path = Path(raw).expanduser()
        try:
            resolved = path.resolve()
            is_dir = resolved.is_dir()
        except (OSError, RuntimeError) as e:
            raise ValueError(f"Invalid mount path '{raw}': {e!s}") from e
        if not is_dir:
            raise ValueError(
                f"Mount path '{raw}' is not an existing directory. "
                "--mount requires a path to a local directory."
            )
        targets_info.append(
            {
                "type": "local_code",
                "details": {"target_path": str(resolved), "mount": True},
                "original": str(resolved),
            }
        )
    return targets_info


def dedupe_local_targets(targets_info: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Collapse local_code targets that resolve to the same path.

    When a directory is supplied both as a copied ``--target`` and via
    ``--mount`` (or as duplicate values of either), keep one entry and prefer
    the bind-mounted one — so the same tree is never both streamed in and
    mounted. Order is preserved; non-local targets pass through untouched.
    """
    result: list[dict[str, Any]] = []
    index_by_path: dict[str, int] = {}
    for target in targets_info:
        details = _as_str_dict(target.get("details"))
        path = str(details.get("target_path") or "")
        if target.get("type") != "local_code" or not path:
            result.append(target)
            continue
        existing = index_by_path.get(path)
        if existing is None:
            index_by_path[path] = len(result)
            result.append(target)
        elif details.get("mount") and not _as_str_dict(result[existing].get("details")).get(
            "mount"
        ):
            result[existing] = target  # bind mount supersedes the copied entry
    return result


def _is_localhost_host(host: str) -> bool:
    host_lower = host.lower().strip("[]")

    if host_lower in ("localhost", _WILDCARD_IPV4_HOST, "::1"):
        return True

    try:
        ip = ipaddress.ip_address(host_lower)
    except ValueError:
        pass
    else:
        return ip.is_loopback

    return False


def rewrite_localhost_targets(targets_info: list[dict[str, Any]], host_gateway: str) -> None:
    from yarl import URL

    for target_info in targets_info:
        target_type = str(target_info.get("type") or "")
        details = _as_str_dict(target_info.get("details"))

        if target_type == "web_application":
            target_url = str(details.get("target_url") or "")
            try:
                url = URL(target_url)
            except (ValueError, TypeError):
                continue

            if url.host and _is_localhost_host(url.host):
                details["target_url"] = str(url.with_host(host_gateway))

        elif target_type == "ip_address":
            target_ip = str(details.get("target_ip") or "")
            if target_ip and _is_localhost_host(target_ip):
                details["target_ip"] = host_gateway
