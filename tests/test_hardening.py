from __future__ import annotations

from importlib import import_module
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from docker import errors as docker_errors

from strix.runtime.docker_client import StrixDockerSandboxClient


main_module = import_module("strix.interface.main")


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
    assert "require a GPT-5.6 Sol, Terra, or Luna deployment" in capsys.readouterr().out


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
    assert "require a GPT-5.6 Sol, Terra, or Luna deployment" in capsys.readouterr().out


def test_docker_client_has_no_shared_bind_mount_default() -> None:
    assert "strix_bind_mounts" not in StrixDockerSandboxClient.__dict__


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
    assert capsys.readouterr().out == "strix 1.1.0.post1\n"
