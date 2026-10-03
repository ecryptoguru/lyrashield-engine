import errno
import ipaddress
import os
import socket
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, contextmanager

import pytest


os.environ["LITELLM_LOCAL_MODEL_COST_MAP"] = "True"

_TEST_ALLOWED_SOCKET_DESTINATIONS: set[tuple[str, int]] = set()


def _is_loopback_host(host: object) -> bool:
    if isinstance(host, str) and host.rstrip(".").lower() == "localhost":
        return True
    try:
        address = ipaddress.ip_address(host)
    except (TypeError, ValueError):
        return False
    return address.is_loopback or (
        isinstance(address, ipaddress.IPv6Address)
        and address.ipv4_mapped is not None
        and address.ipv4_mapped.is_loopback
    )


def _is_ip_literal(host: object) -> bool:
    try:
        ipaddress.ip_address(host)
    except (TypeError, ValueError):
        return False
    return True


def _assert_allowed_socket_destination(family: int, address: object) -> None:
    unix_family = getattr(socket, "AF_UNIX", None)
    if unix_family is not None and family == unix_family:
        docker_host = os.environ.get("DOCKER_HOST")
        if not docker_host:
            docker_socket = "/var/run/docker.sock"
        elif docker_host.startswith("unix://"):
            docker_socket = docker_host.removeprefix("unix://")
        else:
            docker_socket = None
        if (
            docker_socket is not None
            and isinstance(address, (str, bytes))
            and os.path.realpath(os.fsdecode(address)) == os.path.realpath(docker_socket)
        ):
            return
    elif family in (socket.AF_INET, socket.AF_INET6) and isinstance(address, tuple):
        if address and _is_loopback_host(address[0]):
            return
        destination = (str(address[0]), int(address[1])) if len(address) >= 2 else None
        if destination in _TEST_ALLOWED_SOCKET_DESTINATIONS:
            return
    raise OSError(errno.EPERM, "test socket guard blocked non-loopback network access")


@pytest.fixture(autouse=True)
def _guard_test_sockets(monkeypatch: pytest.MonkeyPatch) -> None:
    """Allow loopback, the Docker socket, and explicitly scoped test targets."""
    _TEST_ALLOWED_SOCKET_DESTINATIONS.clear()
    original_connect = socket.socket.connect
    original_connect_ex = socket.socket.connect_ex
    original_sendto = socket.socket.sendto
    original_getaddrinfo = socket.getaddrinfo

    def guarded_connect(sock: socket.socket, address: object) -> None:
        _assert_allowed_socket_destination(sock.family, address)
        original_connect(sock, address)

    def guarded_connect_ex(sock: socket.socket, address: object) -> int:
        try:
            _assert_allowed_socket_destination(sock.family, address)
        except OSError as exc:
            return exc.errno or errno.EPERM
        return original_connect_ex(sock, address)

    def guarded_sendto(sock: socket.socket, data: bytes, *args: object) -> int:
        if args:
            _assert_allowed_socket_destination(sock.family, args[-1])
        return original_sendto(sock, data, *args)

    def guarded_getaddrinfo(host: object, *args: object, **kwargs: object) -> list[tuple]:
        if host not in (None, "") and not _is_loopback_host(host) and not _is_ip_literal(host):
            raise OSError(errno.EPERM, "test socket guard blocked external DNS lookup")
        return original_getaddrinfo(host, *args, **kwargs)

    monkeypatch.setattr(socket.socket, "connect", guarded_connect)
    monkeypatch.setattr(socket.socket, "connect_ex", guarded_connect_ex)
    monkeypatch.setattr(socket.socket, "sendto", guarded_sendto)
    monkeypatch.setattr(socket, "getaddrinfo", guarded_getaddrinfo)


@pytest.fixture
def allow_test_socket_destination() -> Callable[
    [str, int], AbstractContextManager[tuple[str, int]]
]:
    """Temporarily allow one exact IP and port for a local integration test."""

    @contextmanager
    def allow(host: str, port: int) -> Iterator[tuple[str, int]]:
        destination = (str(ipaddress.ip_address(host)), port)
        _TEST_ALLOWED_SOCKET_DESTINATIONS.add(destination)
        try:
            yield destination
        finally:
            _TEST_ALLOWED_SOCKET_DESTINATIONS.discard(destination)

    return allow


_LLM_ENV_KEYS = [
    "STRIX_LLM",
    "LYRASHIELD_LLM",
    "STRIX_DELEGATE_LLM",
    "LYRASHIELD_DELEGATE_LLM",
    "STRIX_REASONING_EFFORT",
    "LYRASHIELD_REASONING_EFFORT",
    "STRIX_DELEGATE_REASONING_EFFORT",
    "LYRASHIELD_DELEGATE_REASONING_EFFORT",
    "STRIX_FORCE_REQUIRED_TOOL_CHOICE",
    "LYRASHIELD_FORCE_REQUIRED_TOOL_CHOICE",
    "STRIX_LLM_TIMEOUT",
    "LYRASHIELD_LLM_TIMEOUT",
    "STRIX_IMAGE",
    "LYRASHIELD_IMAGE",
    "STRIX_RUNTIME_BACKEND",
    "LYRASHIELD_RUNTIME_BACKEND",
    "STRIX_MAX_LOCAL_COPY_MB",
    "LYRASHIELD_MAX_LOCAL_COPY_MB",
    "STRIX_MAX_CONTEXT_IMAGES",
    "LYRASHIELD_MAX_CONTEXT_IMAGES",
    "STRIX_MAX_OUTPUT_TOKENS",
    "LYRASHIELD_MAX_OUTPUT_TOKENS",
    "STRIX_MAX_INPUT_TOKENS",
    "LYRASHIELD_MAX_INPUT_TOKENS",
    "STRIX_TELEMETRY",
    "LYRASHIELD_TELEMETRY",
    # Credential / endpoint aliases
    "LLM_API_KEY",
    "OPENAI_API_KEY",
    "AZURE_OPENAI_API_KEY",
    "AZURE_AI_API_KEY",
    "LLM_API_BASE",
    "OPENAI_API_BASE",
    "OPENAI_BASE_URL",
    "LITELLM_BASE_URL",
    "OLLAMA_API_BASE",
    "AZURE_OPENAI_ENDPOINT",
    "AZURE_OPENAI_API_BASE",
    "AZURE_AI_API_BASE",
    "AZURE_API_BASE",
    "LLM_API_VERSION",
    "AZURE_API_VERSION",
    "AZURE_OPENAI_API_VERSION",
    "AZURE_AI_API_VERSION",
    # Web search credentials and toggles
    "PARALLEL_API_KEY",
    "LYRASHIELD_WEB_SEARCH_API_KEY",
    "STRIX_WEB_SEARCH_API_KEY",
    "LYRASHIELD_WEB_SEARCH_ENABLED",
    "STRIX_WEB_SEARCH_ENABLED",
    "LYRASHIELD_WEB_SEARCH_MODE",
    "STRIX_WEB_SEARCH_MODE",
]


@pytest.fixture(autouse=True)
def _clear_llm_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Clear LLM-related env vars so tests don't inherit leaked Azure endpoints."""
    for key in _LLM_ENV_KEYS:
        monkeypatch.delenv(key, raising=False)


@pytest.fixture(autouse=True)
def _isolate_mcp_config(
    monkeypatch: pytest.MonkeyPatch, tmp_path_factory: pytest.TempPathFactory
) -> None:
    """Keep the suite from reading a real MCP config.

    ``run_strix_scan`` connects the MCP servers listed in
    ``~/.strix/mcp-servers.json``. Point the loader at a path that does not
    exist so it resolves to "no connections". Tests that exercise the loader
    itself set their own ``STRIX_MCP_CONFIG`` after this runs.
    """
    missing = tmp_path_factory.mktemp("mcp-isolation") / "no-servers.json"
    monkeypatch.setenv("STRIX_MCP_CONFIG", str(missing))
    monkeypatch.delenv("STRIX_MCP_ONLY", raising=False)
    monkeypatch.delenv("STRIX_MCP_EXCLUDE", raising=False)


@pytest.fixture(autouse=True)
def _plain_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make Rich output identical on every machine (upstream parity fixture)."""
    monkeypatch.setenv("TERM", "dumb")
    for name in ("COLORTERM", "FORCE_COLOR", "NO_COLOR", "TTY_COMPATIBLE"):
        monkeypatch.delenv(name, raising=False)
