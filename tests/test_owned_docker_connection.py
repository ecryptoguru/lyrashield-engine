"""Docker endpoint resolution and the panel printed when the daemon is unreachable."""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

import pytest
from docker.context import context as context_module
from docker.context.context import Context
from docker.errors import DockerException
from requests.exceptions import ConnectionError as RequestsConnectionError
from urllib3.exceptions import ProtocolError

from lyrashield.runtime import docker_connection
from lyrashield.runtime.docker_connection import (
    DockerConnectionError,
    DockerEndpoint,
    resolve_docker_endpoint,
)


def _sdk_error(inner: BaseException) -> DockerException:
    """Build the exception exactly as docker-py raises it for a dead daemon."""
    protocol = ProtocolError("Connection aborted.", inner)
    requests_exc = RequestsConnectionError(protocol)
    requests_exc.__cause__ = protocol
    sdk_exc = DockerException(f"Error while fetching server API version: {requests_exc}")
    sdk_exc.__cause__ = requests_exc
    return sdk_exc


def test_docker_host_wins_over_context(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(docker_connection, "get_current_context_name", lambda: "desktop-linux")
    endpoint = resolve_docker_endpoint({"DOCKER_HOST": "tcp://10.0.0.5:2375"})
    assert endpoint == DockerEndpoint("tcp://10.0.0.5:2375", "DOCKER_HOST")


def test_current_context_is_used_like_the_cli(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(docker_connection, "get_current_context_name", lambda: "desktop-linux")
    monkeypatch.setattr(
        "lyrashield.runtime.docker_connection.ContextAPI.get_context",
        lambda _name: SimpleNamespace(
            endpoints={"docker": {"Host": "unix:///Users/me/.docker/run/docker.sock"}},
            tls_cfg={},
            tls_path="",
        ),
    )
    endpoint = resolve_docker_endpoint({})
    assert endpoint.host == "unix:///Users/me/.docker/run/docker.sock"
    assert endpoint.source == "docker context 'desktop-linux'"


def test_default_context_uses_the_sdk_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(docker_connection, "get_current_context_name", lambda: "default")
    assert resolve_docker_endpoint({}) == DockerEndpoint(None, "default socket")


def test_missing_or_broken_current_context_is_an_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(docker_connection, "get_current_context_name", lambda: "gone")
    monkeypatch.setattr(
        "lyrashield.runtime.docker_connection.ContextAPI.get_context", lambda _name: None
    )
    with pytest.raises(
        DockerConnectionError, match="docker context 'gone' is selected but does not exist"
    ):
        resolve_docker_endpoint({})

    def boom(_name: str) -> None:
        raise DockerException("bad meta.json")

    monkeypatch.setattr("lyrashield.runtime.docker_connection.ContextAPI.get_context", boom)
    with pytest.raises(DockerConnectionError, match="bad meta") as info:
        resolve_docker_endpoint({})
    assert info.value.endpoint.label == "docker context 'gone'"


def test_docker_host_goes_through_from_env_so_tls_settings_apply(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        docker_connection,
        "resolve_docker_endpoint",
        lambda _environ=None: DockerEndpoint("tcp://10.0.0.5:2376", "DOCKER_HOST"),
    )
    client = object()
    monkeypatch.setattr("lyrashield.runtime.docker_connection.docker.from_env", lambda: client)

    def unexpected(**_kwargs: Any) -> None:
        raise AssertionError("DOCKER_HOST must not bypass from_env")

    monkeypatch.setattr("lyrashield.runtime.docker_connection.docker.DockerClient", unexpected)
    assert docker_connection.connect_docker() is client


def test_context_endpoint_keeps_its_tls_config(monkeypatch: pytest.MonkeyPatch) -> None:
    tls = object()
    monkeypatch.setattr(
        docker_connection,
        "resolve_docker_endpoint",
        lambda _environ=None: DockerEndpoint("tcp://remote:2376", "docker context 'remote'", tls),
    )
    seen: dict[str, Any] = {}

    def client(**kwargs: Any) -> str:
        seen.update(kwargs)
        return "client"

    monkeypatch.setattr("lyrashield.runtime.docker_connection.docker.DockerClient", client)
    assert docker_connection.connect_docker() == "client"
    assert seen == {"base_url": "tcp://remote:2376", "tls": tls}


@pytest.mark.parametrize(
    "inner",
    [
        FileNotFoundError(2, "No such file or directory"),
        PermissionError(13, "Permission denied"),
        ConnectionRefusedError(111, "Connection refused"),
    ],
)
def test_connect_docker_surfaces_the_root_cause(
    monkeypatch: pytest.MonkeyPatch, inner: OSError
) -> None:
    monkeypatch.setattr(
        docker_connection,
        "resolve_docker_endpoint",
        lambda _environ=None: DockerEndpoint("unix:///nope.sock", "docker context 'dead'"),
    )

    def dead_client(**_kwargs: Any) -> None:
        raise _sdk_error(inner)

    monkeypatch.setattr("lyrashield.runtime.docker_connection.docker.DockerClient", dead_client)

    with pytest.raises(DockerConnectionError) as info:
        docker_connection.connect_docker()

    assert info.value.cause is inner
    assert info.value.detail.startswith(type(inner).__name__)
    assert info.value.endpoint.host == "unix:///nope.sock"


def test_explicit_docker_context_overrides_host(monkeypatch):
    monkeypatch.setattr(
        docker_connection.ContextAPI,
        "get_context",
        lambda _name: SimpleNamespace(
            endpoints={"docker": {"Host": "unix:///context.sock"}}, tls_cfg={}, tls_path=""
        ),
    )
    endpoint = resolve_docker_endpoint(
        {"DOCKER_CONTEXT": "chosen", "DOCKER_HOST": "tcp://ignored:2375"}
    )
    assert endpoint.host == "unix:///context.sock"
    assert endpoint.source == "docker context 'chosen'"


@pytest.mark.parametrize("orchestrator", [None, "kubernetes"])
@pytest.mark.parametrize("explicit_verify_flag", [True, False])
@pytest.mark.parametrize("material_names", [("ca.pem",), ("ca.pem", "cert.pem", "key.pem")])
def test_real_context_selects_docker_endpoint_and_keeps_ca_only_tls(
    tmp_path, monkeypatch, orchestrator, material_names, explicit_verify_flag
):

    docker_endpoint = {"Host": "tcp://docker.test:2376"}
    if explicit_verify_flag:
        docker_endpoint["SkipTLSVerify"] = False
    metadata = tmp_path / "meta.json"
    metadata.write_text(
        json.dumps(
            {
                "Name": "remote",
                "Metadata": {"StackOrchestrator": orchestrator},
                "Endpoints": {
                    "docker": docker_endpoint,
                    "kubernetes": {"Host": "https://kube.test:6443"},
                },
            }
        )
    )
    tls = tmp_path / "tls"
    (tls / "docker").mkdir(parents=True)
    for filename in material_names:
        (tls / "docker" / filename).write_text("fixture TLS material")
    monkeypatch.setattr(context_module, "get_meta_file", lambda _name: str(metadata))
    monkeypatch.setattr(context_module, "get_meta_dir", lambda _name: str(tmp_path))
    monkeypatch.setattr(context_module, "get_tls_dir", lambda _name: str(tls))
    context = Context.load_context("remote")
    monkeypatch.setattr(docker_connection, "get_current_context_name", lambda: "remote")
    monkeypatch.setattr(docker_connection.ContextAPI, "get_context", lambda _name: context)
    endpoint = resolve_docker_endpoint({})
    assert endpoint.host == "tcp://docker.test:2376"
    assert endpoint.tls is not None
    assert endpoint.tls.verify is True
    assert endpoint.tls.ca_cert == str(tls / "docker" / "ca.pem")
    transport = docker_connection.docker.DockerClient(
        base_url=endpoint.host, tls=endpoint.tls, version="1.43"
    )
    try:
        assert transport.api.base_url == "https://docker.test:2376"
        assert transport.api.verify == str(tls / "docker" / "ca.pem")
        if "cert.pem" in material_names:
            assert transport.api.cert == (
                str(tls / "docker" / "cert.pem"),
                str(tls / "docker" / "key.pem"),
            )
    finally:
        transport.close()


def test_partial_context_client_certificate_fails_closed(tmp_path, monkeypatch):
    context = SimpleNamespace(
        endpoints={"docker": {"Host": "tcp://remote.test:2376", "SkipTLSVerify": False}},
        tls_cfg={},
        tls_path=str(tmp_path),
    )
    (tmp_path / "docker").mkdir()
    (tmp_path / "docker" / "cert.pem").write_text("fixture cert")
    monkeypatch.setattr(docker_connection, "get_current_context_name", lambda: "remote")
    monkeypatch.setattr(docker_connection.ContextAPI, "get_context", lambda _name: context)
    with pytest.raises(DockerConnectionError, match="certificate and key"):
        resolve_docker_endpoint({})


def test_broken_ca_context_never_falls_back_to_plaintext(tmp_path, monkeypatch):
    material = tmp_path / "docker"
    material.mkdir()
    (material / "ca.pem").symlink_to(tmp_path / "missing-ca")
    context = SimpleNamespace(
        endpoints={"docker": {"Host": "tcp://remote.test:2376", "SkipTLSVerify": False}},
        tls_cfg={},
        tls_path=str(tmp_path),
    )
    monkeypatch.setattr(docker_connection, "get_current_context_name", lambda: "remote")
    monkeypatch.setattr(docker_connection.ContextAPI, "get_context", lambda _name: context)
    with pytest.raises(DockerConnectionError, match="malformed Docker TLS material"):
        resolve_docker_endpoint({})


@pytest.mark.parametrize("skip_verify", [True, False, None, "false"])
def test_real_context_raw_tls_flag_preserves_encryption_without_pems(
    tmp_path, monkeypatch, skip_verify
):
    endpoint = {"Host": "tcp://remote.test:2376"}
    if skip_verify is not None:
        endpoint["SkipTLSVerify"] = skip_verify
    metadata = tmp_path / "meta.json"
    metadata.write_text(
        json.dumps({"Name": "remote", "Metadata": {}, "Endpoints": {"docker": endpoint}})
    )
    monkeypatch.setattr(context_module, "get_meta_file", lambda _name: str(metadata))
    monkeypatch.setattr(context_module, "get_meta_dir", lambda _name: str(tmp_path))
    monkeypatch.setattr(context_module, "get_tls_dir", lambda _name: str(tmp_path / "tls"))
    context = Context.load_context("remote")
    monkeypatch.setattr(docker_connection, "get_current_context_name", lambda: "remote")
    monkeypatch.setattr(docker_connection.ContextAPI, "get_context", lambda _name: context)
    if isinstance(skip_verify, str):
        with pytest.raises(DockerConnectionError, match="SkipTLSVerify"):
            resolve_docker_endpoint({})
        return
    resolved = resolve_docker_endpoint({})
    client = docker_connection.docker.DockerClient(
        base_url=resolved.host, tls=resolved.tls or False, version="1.43"
    )
    try:
        assert client.api.base_url == (
            "https://remote.test:2376" if skip_verify else "http://remote.test:2376"
        )
        if skip_verify:
            assert client.api.verify is False
    finally:
        client.close()
