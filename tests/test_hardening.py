from __future__ import annotations

from importlib import import_module
from types import SimpleNamespace
from unittest.mock import patch

import pytest

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


def test_docker_client_has_no_shared_bind_mount_default() -> None:
    assert "strix_bind_mounts" not in StrixDockerSandboxClient.__dict__
