from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from lyrashield_adapter import cli


if TYPE_CHECKING:
    from collections.abc import MutableMapping


@pytest.mark.parametrize(
    ("product", "upstream"),
    [
        ("LYRASHIELD_LLM", "STRIX_LLM"),
        ("LYRASHIELD_DELEGATE_LLM", "STRIX_DELEGATE_LLM"),
        ("LYRASHIELD_IMAGE", "STRIX_IMAGE"),
        ("LYRASHIELD_RUNTIME_BACKEND", "STRIX_RUNTIME_BACKEND"),
        ("LYRASHIELD_MAX_LOCAL_COPY_MB", "STRIX_MAX_LOCAL_COPY_MB"),
        ("LYRASHIELD_MAX_CONTEXT_IMAGES", "STRIX_MAX_CONTEXT_IMAGES"),
        ("LYRASHIELD_REASONING_EFFORT", "STRIX_REASONING_EFFORT"),
        (
            "LYRASHIELD_DELEGATE_REASONING_EFFORT",
            "STRIX_DELEGATE_REASONING_EFFORT",
        ),
        (
            "LYRASHIELD_FORCE_REQUIRED_TOOL_CHOICE",
            "STRIX_FORCE_REQUIRED_TOOL_CHOICE",
        ),
        ("LYRASHIELD_LLM_TIMEOUT", "LLM_TIMEOUT"),
    ],
)
def test_prepare_environment_maps_product_variable(product: str, upstream: str) -> None:
    env: MutableMapping[str, str] = {product: "product-value"}
    cli.prepare_environment(env)
    assert env[upstream] == "product-value"


def test_prepare_environment_keeps_explicit_upstream_value() -> None:
    env: MutableMapping[str, str] = {
        "LYRASHIELD_LLM": "product-model",
        "STRIX_LLM": "operator-model",
    }
    cli.prepare_environment(env)
    assert env["STRIX_LLM"] == "operator-model"


def test_prepare_environment_forces_telemetry_off() -> None:
    env: MutableMapping[str, str] = {
        "LYRASHIELD_TELEMETRY": "1",
        "STRIX_TELEMETRY": "1",
    }
    cli.prepare_environment(env)
    assert env["STRIX_TELEMETRY"] == "0"


def test_main_prints_product_version(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli, "get_version", lambda: "1.0.4.post1")
    monkeypatch.setattr(cli.sys, "argv", ["lyrashield", "--version"])
    cli.main()
    assert capsys.readouterr().out == "lyrashield 1.0.4.post1\n"


def test_main_delegates_non_version_arguments(monkeypatch: pytest.MonkeyPatch) -> None:
    called = False

    def fake_upstream_main() -> None:
        nonlocal called
        called = True

    monkeypatch.setattr(cli, "_run_upstream", fake_upstream_main)
    monkeypatch.setattr(cli.sys, "argv", ["lyrashield", "--non-interactive"])
    cli.main()
    assert called is True
