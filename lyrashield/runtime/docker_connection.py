from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import docker  # type: ignore[import-untyped, unused-ignore]
from docker.context import ContextAPI  # type: ignore[import-untyped, unused-ignore]
from docker.context.config import (  # type: ignore[import-untyped, unused-ignore]
    get_current_context_name,
)
from docker.errors import DockerException
from docker.tls import TLSConfig  # type: ignore[import-untyped, unused-ignore]


DEFAULT_CONTEXT = "default"


@dataclass(frozen=True)
class DockerEndpoint:
    """Where LyraShield talks to Docker and how that address was chosen."""

    host: str | None
    source: str
    tls: Any = None

    @property
    def label(self) -> str:
        return f"{self.host} ({self.source})" if self.host else self.source


class DockerConnectionError(RuntimeError):
    """The daemon at ``endpoint`` could not be reached."""

    def __init__(self, endpoint: DockerEndpoint, cause: BaseException) -> None:
        self.endpoint = endpoint
        self.cause = root_cause(cause)
        super().__init__(f"Cannot connect to Docker at {endpoint.label}: {self.detail}")

    @property
    def detail(self) -> str:
        text = str(self.cause).strip()
        name = type(self.cause).__name__
        return text if name in text else f"{name}: {text}" if text else name


def resolve_docker_endpoint(environ: dict[str, str] | None = None) -> DockerEndpoint:
    """``DOCKER_CONTEXT``, then ``DOCKER_HOST``, then selected context/default."""
    env = os.environ if environ is None else environ
    explicit_context = env.get("DOCKER_CONTEXT", "").strip()
    host = env.get("DOCKER_HOST", "").strip()
    if host and not explicit_context:
        return DockerEndpoint(host, "DOCKER_HOST")

    name = explicit_context or get_current_context_name()
    if name == DEFAULT_CONTEXT and not explicit_context:
        return DockerEndpoint(None, "default socket")

    source = f"docker context '{name}'"
    try:
        context = ContextAPI.get_context(name)
    except DockerException as exc:
        raise DockerConnectionError(DockerEndpoint(None, source), exc) from exc
    if context is None:
        missing = DockerException(f"{source} is selected but does not exist")
        raise DockerConnectionError(DockerEndpoint(None, source), missing)
    try:
        return _context_endpoint(context, source)
    except (DockerException, OSError, ValueError, TypeError, AttributeError) as exc:
        raise DockerConnectionError(DockerEndpoint(None, source), exc) from exc


def _context_endpoint(context: Any, source: str) -> DockerEndpoint:
    endpoints = context.endpoints
    metadata_root = getattr(context, "meta_path", "")
    if metadata_root and metadata_root != "IN MEMORY":
        # The SDK normalizes an omitted SkipTLSVerify to True. Read the stored
        # flag before deciding whether TLS is enabled or verification is skipped.
        metadata = json.loads((Path(metadata_root) / "meta.json").read_text(encoding="utf-8"))
        endpoints = metadata.get("Endpoints") if isinstance(metadata, dict) else None
    endpoint = endpoints.get("docker") if isinstance(endpoints, dict) else None
    if not isinstance(endpoint, dict) or not isinstance(endpoint.get("Host"), str):
        raise DockerException(f"{source} has no valid Docker endpoint")
    skip_verify = endpoint.get("SkipTLSVerify", False)
    if not isinstance(skip_verify, bool):
        raise DockerException(f"{source} has malformed SkipTLSVerify; expected a boolean")
    host = endpoint["Host"].strip()
    if not host:
        raise DockerException(f"{source} has an empty Docker endpoint")
    # Docker-py's Host/TLSConfig properties follow StackOrchestrator and
    # discard CA-only material. Select the Docker endpoint explicitly and
    # rebuild TLS from its own stored material so neither can downgrade it.
    tls = context.tls_cfg.get("docker")
    tls_root = getattr(context, "tls_path", "")
    material = Path(tls_root) / "docker" if tls_root and tls_root != "IN MEMORY" else None
    ca = cert = key = None
    if material is not None and material.exists():
        paths = {name: material / name for name in ("ca.pem", "cert.pem", "key.pem")}
        for path in paths.values():
            if (path.exists() or path.is_symlink()) and not path.is_file():
                raise DockerException(f"{source} has malformed Docker TLS material")
        unsupported = [path for path in material.iterdir() if path.name not in paths]
        if unsupported and tls is None:
            raise DockerException(f"{source} has unsupported Docker TLS material names")
        ca, cert, key = (str(paths[name]) if paths[name].is_file() else None for name in paths)
        if bool(cert) != bool(key):
            raise DockerException(f"{source} requires both a client certificate and key")
    if tls is not None:
        # Rebuild verification too: the SDK may have derived it from the
        # normalized flag rather than the context's stored default.
        tls = TLSConfig(client_cert=tls.cert, ca_cert=tls.ca_cert, verify=not skip_verify)
    elif (
        ca
        or cert
        or host.startswith("https://")
        or (skip_verify and host.startswith(("tcp://", "http://")))
    ):
        # SkipTLSVerify disables certificate verification, never encryption.
        tls = TLSConfig(
            client_cert=(cert, key) if cert and key else None,
            ca_cert=ca,
            verify=not skip_verify,
        )
    return DockerEndpoint(host, source, tls)


def connect_docker() -> Any:
    """Return a ``docker.DockerClient`` for the resolved endpoint or raise DockerConnectionError."""
    endpoint = resolve_docker_endpoint()
    try:
        if endpoint.source == "DOCKER_HOST" or endpoint.host is None:
            return docker.from_env()  # also reads DOCKER_TLS_VERIFY and DOCKER_CERT_PATH
        return docker.DockerClient(base_url=endpoint.host, tls=endpoint.tls or False)
    except DockerException as exc:
        raise DockerConnectionError(endpoint, exc) from exc


def root_cause(exc: BaseException) -> BaseException:
    """The innermost exception: the SDK wraps the OSError in requests/urllib3 errors."""
    current = exc
    seen: list[BaseException] = []
    while not any(current is s for s in seen):
        seen.append(current)
        nested = [arg for arg in current.args if isinstance(arg, BaseException)]
        following = current.__cause__ or current.__context__ or (nested[-1] if nested else None)
        if following is None:
            break
        current = following
    return current
