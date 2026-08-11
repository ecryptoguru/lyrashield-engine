"""Tests for the `strix auth` CLI: subcommand routing and provider naming."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest

from lyrashield.interface import auth_cli
from lyrashield.policy import codex
from lyrashield.policy.settings import PRODUCT_BOUNDARY_ENV_VAR


if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture(autouse=True)
def _tmp_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(codex, "AUTH_PATH", tmp_path / "home" / ".strix" / "subscription-auth.json")
    monkeypatch.delenv(PRODUCT_BOUNDARY_ENV_VAR, raising=False)
    monkeypatch.delenv("LYRASHIELD_ALLOW_CHATGPT_SUBSCRIPTION", raising=False)
    monkeypatch.delenv("STRIX_ALLOW_CHATGPT_SUBSCRIPTION", raising=False)


def test_login_provider_is_chatgpt() -> None:
    assert auth_cli.LOGIN_PROVIDER == "chatgpt"
    assert codex.PROVIDER in auth_cli._ACCEPTED_PROVIDERS
    assert "chatgpt" in auth_cli._ACCEPTED_PROVIDERS


def test_unknown_subcommand_returns_usage_error() -> None:
    assert auth_cli.run_auth(["bogus"]) == 2


def test_help_returns_zero() -> None:
    assert auth_cli.run_auth(["--help"]) == 0


def test_auth_logo_is_packaged_product_asset() -> None:
    assert auth_cli._LOGO_PATH.parts[-4:] == ("interface", "viewer", "static", "logo.png")
    assert auth_cli._LOGO_PATH.is_file()


def test_status_not_signed_in() -> None:
    assert auth_cli.run_auth(["status"]) == 1


def test_login_rejects_unsupported_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    def _should_not_run(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        msg = "OAuth flow must not start for an unsupported provider"
        raise AssertionError(msg)

    monkeypatch.setattr(auth_cli, "_run_oauth_flow", _should_not_run)
    assert auth_cli.run_auth(["login", "gemini"]) == 2


def test_finish_requires_state_on_loopback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(codex, "exchange_code", lambda *_: {"ok": True})

    # Loopback (require_state=True): missing or mismatched state is rejected.
    with pytest.raises(codex.CodexAuthError) as missing:
        auth_cli._finish("code", None, "verifier", "expected", require_state=True)
    assert missing.value.code == "state_mismatch"
    with pytest.raises(codex.CodexAuthError) as mismatch:
        auth_cli._finish("code", "wrong", "verifier", "expected", require_state=True)
    assert mismatch.value.code == "state_mismatch"

    # Matching state proceeds to the exchange.
    assert auth_cli._finish("code", "expected", "verifier", "expected", require_state=True) == {
        "ok": True
    }


def test_finish_manual_paste_allows_absent_state(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(codex, "exchange_code", lambda *_: {"ok": True})
    # Manual paste (require_state=False): a bare code with no state is accepted,
    # but a present-and-wrong state is still rejected.
    assert auth_cli._finish("code", None, "verifier", "expected", require_state=False) == {
        "ok": True
    }
    with pytest.raises(codex.CodexAuthError):
        auth_cli._finish("code", "wrong", "verifier", "expected", require_state=False)


def test_finish_rejects_missing_code() -> None:
    with pytest.raises(codex.CodexAuthError) as exc:
        auth_cli._finish(None, "expected", "verifier", "expected", require_state=True)
    assert exc.value.code == "no_code"


def test_model_subcommand_removed() -> None:
    assert auth_cli.run_auth(["model", "gpt-5.5"]) == 2


@pytest.mark.parametrize("provider", ["chatgpt", "codex", "ChatGPT"])
def test_login_accepts_supported_provider(monkeypatch: pytest.MonkeyPatch, provider: str) -> None:
    reached: dict[str, bool] = {"flow": False}

    def _fake_flow(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        reached["flow"] = True
        return {
            "ok": True,
            "access_token": "test-token",
            "expires_at": 0,
        }

    monkeypatch.setattr(auth_cli, "_run_oauth_flow", _fake_flow)
    monkeypatch.setattr(codex, "save_record", lambda _record: None)

    assert auth_cli.run_auth(["login", provider]) == 0
    assert reached["flow"] is True


def test_auth_rejected_under_product_boundary_when_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """LyraShield rejects ChatGPT subscription sign-in when explicitly disabled."""
    monkeypatch.setenv(PRODUCT_BOUNDARY_ENV_VAR, "1")
    monkeypatch.setenv("LYRASHIELD_ALLOW_CHATGPT_SUBSCRIPTION", "0")
    assert auth_cli.run_auth(["login", "chatgpt"]) == 1


def test_auth_allowed_under_product_boundary_by_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ChatGPT subscription auth is available by default."""
    monkeypatch.setenv(PRODUCT_BOUNDARY_ENV_VAR, "1")

    def _fake_flow(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        return {"ok": True, "access_token": "test-token", "expires_at": 0}

    monkeypatch.setattr(auth_cli, "_run_oauth_flow", _fake_flow)
    monkeypatch.setattr(codex, "save_record", lambda _record: None)
    assert auth_cli.run_auth(["login", "chatgpt"]) == 0
