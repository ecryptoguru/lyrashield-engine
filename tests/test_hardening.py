from __future__ import annotations

import argparse
from importlib import import_module
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from agents.sandbox.sandboxes.docker import DockerSandboxClient
from docker import errors as docker_errors

from lyrashield.interface.utils import validate_run_name
from lyrashield.runtime.docker_client import (
    StrixDockerSandboxClient,
    assert_sdk_docker_compatibility,
    network_capabilities_enabled,
)


main_module = import_module("lyrashield.interface.main")


def test_main_validates_configuration_before_docker_setup() -> None:
    args = SimpleNamespace(config=None)

    with (
        patch.object(main_module, "configure_dependency_logging"),
        patch.object(main_module, "parse_arguments", return_value=args),
        patch.object(main_module, "validate_environment", side_effect=RuntimeError("missing key")),
        patch.object(main_module, "check_docker_installed") as check_docker,
        patch.object(main_module, "pull_docker_image") as pull_image,
        pytest.raises(RuntimeError, match="missing key"),
    ):
        main_module.main()

    check_docker.assert_not_called()
    pull_image.assert_not_called()


def test_invalid_model_exits_with_clean_cli_message(capsys: pytest.CaptureFixture[str]) -> None:
    settings = SimpleNamespace(
        llm=SimpleNamespace(model="openai/gpt-4o", api_key="configured", api_base="configured")
    )

    with (
        patch.object(main_module, "load_settings", return_value=settings),
        pytest.raises(SystemExit) as exc_info,
    ):
        main_module.validate_environment()

    assert exc_info.value.code == 1
    assert "require a GPT-5.6 Terra or Luna deployment" in capsys.readouterr().out


def test_invalid_delegate_model_exits_before_sandbox_setup(
    capsys: pytest.CaptureFixture[str],
) -> None:
    settings = SimpleNamespace(
        llm=SimpleNamespace(
            model="openai/gpt-5.6-terra",
            delegate_model="openai/gpt-4o",
            api_key="configured",
            api_base="configured",
        )
    )

    with (
        patch.object(main_module, "load_settings", return_value=settings),
        pytest.raises(SystemExit) as exc_info,
    ):
        main_module.validate_environment()

    assert exc_info.value.code == 1
    assert "require a GPT-5.6 Terra or Luna deployment" in capsys.readouterr().out


def test_docker_client_has_no_shared_bind_mount_default() -> None:
    assert "strix_bind_mounts" not in StrixDockerSandboxClient.__dict__


def test_docker_adapter_rejects_an_incompatible_sdk_signature(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def incompatible_create_container(_self: object, _image: str) -> object:
        return object()

    monkeypatch.setattr(DockerSandboxClient, "_create_container", incompatible_create_container)

    with pytest.raises(RuntimeError, match="unsupported OpenAI Agents SDK Docker adapter"):
        assert_sdk_docker_compatibility()


@pytest.mark.asyncio
async def test_docker_client_rejects_an_image_unavailable_after_pull() -> None:
    client = StrixDockerSandboxClient.__new__(StrixDockerSandboxClient)
    client.docker_client = MagicMock()
    client.image_exists = MagicMock(side_effect=[False, False])

    with pytest.raises(docker_errors.DockerException, match="unavailable after pull"):
        await client._create_container("missing:latest")

    client.docker_client.images.pull.assert_called_once()


def test_strix_version_reports_installed_lyrashield_distribution(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(main_module.sys, "argv", ["strix", "--version"])

    with pytest.raises(SystemExit) as exc_info:
        main_module.main()

    assert exc_info.value.code == 0
    assert capsys.readouterr().out == "strix 1.2.0\n"


def test_network_capabilities_disabled_by_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """NET_ADMIN/NET_RAW must be disabled by default."""
    monkeypatch.delenv("STRIX_SANDBOX_ENABLE_NETWORK_CAPABILITIES", raising=False)
    monkeypatch.delenv("STRIX_SANDBOX_DISABLE_NETWORK_CAPABILITIES", raising=False)
    assert network_capabilities_enabled() is False


def test_network_capabilities_enabled_via_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """NET_ADMIN/NET_RAW must be enabled when STRIX_SANDBOX_ENABLE_NETWORK_CAPABILITIES=1."""
    monkeypatch.setenv("STRIX_SANDBOX_ENABLE_NETWORK_CAPABILITIES", "1")
    assert network_capabilities_enabled() is True


def test_network_capabilities_disabled_via_legacy_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Legacy STRIX_SANDBOX_DISABLE_NETWORK_CAPABILITIES=1 must disable capabilities."""
    monkeypatch.delenv("STRIX_SANDBOX_ENABLE_NETWORK_CAPABILITIES", raising=False)
    monkeypatch.setenv("STRIX_SANDBOX_DISABLE_NETWORK_CAPABILITIES", "1")
    assert network_capabilities_enabled() is False


def test_network_capabilities_enabled_when_legacy_disable_is_false(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Legacy STRIX_SANDBOX_DISABLE_NETWORK_CAPABILITIES=0 must enable capabilities."""
    monkeypatch.delenv("STRIX_SANDBOX_ENABLE_NETWORK_CAPABILITIES", raising=False)
    monkeypatch.setenv("STRIX_SANDBOX_DISABLE_NETWORK_CAPABILITIES", "0")
    assert network_capabilities_enabled() is True


def test_validate_run_name_accepts_valid_name() -> None:
    """Valid run names must be accepted."""
    assert validate_run_name("my-scan-001") == "my-scan-001"
    assert validate_run_name("a") == "a"
    assert validate_run_name("Test.Run_Name-123") == "Test.Run_Name-123"


def test_validate_run_name_rejects_empty() -> None:
    """Empty run names must be rejected."""
    with pytest.raises(argparse.ArgumentTypeError):
        validate_run_name("")


def test_validate_run_name_rejects_path_traversal() -> None:
    """Run names with .. must be rejected."""
    with pytest.raises(argparse.ArgumentTypeError):
        validate_run_name("../etc/passwd")
    with pytest.raises(argparse.ArgumentTypeError):
        validate_run_name("foo/../bar")


def test_validate_run_name_rejects_path_separators() -> None:
    """Run names with path separators must be rejected."""
    with pytest.raises(argparse.ArgumentTypeError):
        validate_run_name("foo/bar")
    with pytest.raises(argparse.ArgumentTypeError):
        validate_run_name("foo\\bar")


def test_validate_run_name_rejects_dot_prefix() -> None:
    """Run names starting with a dot must be rejected."""
    with pytest.raises(argparse.ArgumentTypeError):
        validate_run_name(".hidden")


def test_validate_run_name_rejects_too_long() -> None:
    """Run names longer than 128 characters must be rejected."""
    with pytest.raises(argparse.ArgumentTypeError):
        validate_run_name("a" * 129)
