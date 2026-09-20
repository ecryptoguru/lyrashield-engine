"""Target classification must never touch the network or DNS from the host.

Regression coverage for the removal of the ``_is_http_git_repo`` probe: host-side
inference used to issue an unauthenticated ``GET <url>/info/refs?service=git-
upload-pack`` to whatever URL the operator passed — including private/internal
addresses — purely to decide whether the input was a repository. Classification
is now purely offline, and an explicit ``--target-type`` kind is validated
against the input shape without weakening any downstream credential, source-path,
or target-authorization checks.
"""

from __future__ import annotations

import socket
import sys
from importlib import import_module
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any
from unittest.mock import Mock

import pytest
import requests

from lyrashield.interface import utils as interface_utils
from lyrashield.interface.utils import infer_target_type, resolve_target_type


if TYPE_CHECKING:
    from pathlib import Path


cli_main: Any = import_module("lyrashield.interface.main")


@pytest.fixture(autouse=True)
def no_network(monkeypatch: pytest.MonkeyPatch) -> dict[str, Mock]:
    """Fail closed on any host-side HTTP or DNS attempt during classification."""
    mocks = {
        "get": Mock(name="requests.get"),
        "head": Mock(name="requests.head"),
        "request": Mock(name="requests.request"),
        "dns": Mock(name="socket.getaddrinfo", side_effect=AssertionError("DNS attempted")),
        "connect": Mock(
            name="socket.create_connection", side_effect=AssertionError("TCP connect attempted")
        ),
    }
    monkeypatch.setattr(requests, "get", mocks["get"])
    monkeypatch.setattr(requests, "head", mocks["head"])
    monkeypatch.setattr(requests, "request", mocks["request"])
    monkeypatch.setattr(socket, "getaddrinfo", mocks["dns"])
    monkeypatch.setattr(socket, "create_connection", mocks["connect"])
    return mocks


def _assert_no_http(mocks: dict[str, Mock]) -> None:
    mocks["get"].assert_not_called()
    mocks["head"].assert_not_called()
    mocks["request"].assert_not_called()


def _stub_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        cli_main,
        "load_settings",
        lambda: SimpleNamespace(runtime=SimpleNamespace(max_local_copy_mb=1024)),
    )


def _parse(monkeypatch: pytest.MonkeyPatch, argv: list[str]) -> Any:
    _stub_settings(monkeypatch)
    monkeypatch.setattr(sys, "argv", ["lyrashield", *argv])
    return cli_main.parse_arguments()


def test_url_inference_never_probes_from_host(no_network: dict[str, Mock]) -> None:
    kind, _ = infer_target_type("http://127.0.0.1/private/repo")

    no_network["get"].assert_not_called()
    assert kind == "web_application"


# ---------------------------------------------------------------------------
# Offline inference
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "target",
    [
        "https://github.com/org/repo",
        "https://gitlab.example.com/org/sub/repo",
        "http://127.0.0.1/private/repo",
        "http://127.0.0.1:8080/org/repo",
        "https://10.0.0.5/org/repo",
        "https://192.168.1.20/org/repo",
        "http://[fd00::1]/org/repo",
        "https://example.com/app?next=/login",
        "https://example.com/app#frag",
    ],
)
def test_ambiguous_http_urls_default_to_web_application_without_probing(
    target: str, no_network: dict[str, Mock]
) -> None:
    kind, details = infer_target_type(target)

    assert kind == "web_application"
    assert details == {"target_url": target}
    _assert_no_http(no_network)


def test_redirected_probe_is_never_attempted(no_network: dict[str, Mock]) -> None:
    # Even a URL whose git-probe would redirect to a link-local/metadata address
    # must receive zero requests — classification cannot follow redirects because
    # it never opens a connection.
    no_network["get"].return_value = Mock(
        status_code=302, headers={"Location": "http://169.254.169.254/latest/meta-data"}
    )

    kind, _ = infer_target_type("https://public.example.com/org/repo")

    assert kind == "web_application"
    _assert_no_http(no_network)
    no_network["dns"].assert_not_called()
    no_network["connect"].assert_not_called()


@pytest.mark.parametrize(
    ("target", "expected_repo"),
    [
        ("https://github.com/org/repo.git", "https://github.com/org/repo.git"),
        ("http://[fd00::1]/org/repo.git", "http://[fd00::1]/org/repo.git"),
        ("https://user:pass@github.com/org/repo", "https://user:pass@github.com/org/repo"),
        ("git@github.com:org/repo.git", "git@github.com:org/repo.git"),
        ("git://git.example.com/org/repo", "git://git.example.com/org/repo"),
        ("uncloned-mirror.git", "uncloned-mirror.git"),
    ],
)
def test_offline_recognized_repository_forms(
    target: str, expected_repo: str, no_network: dict[str, Mock]
) -> None:
    kind, details = infer_target_type(target)

    assert kind == "repository"
    assert details == {"target_repo": expected_repo}
    _assert_no_http(no_network)


def test_credential_bearing_url_still_classifies_as_repository(
    no_network: dict[str, Mock],
) -> None:
    # The URL credential rule is a classification input, not a probe result —
    # it must keep working with zero requests.
    kind, _ = infer_target_type("https://oauth2:token@gitlab.example.com/org/repo.git")
    assert kind == "repository"
    _assert_no_http(no_network)


@pytest.mark.parametrize(
    ("target", "expected_ip"),
    [
        ("192.168.1.10", "192.168.1.10"),
        ("10.0.0.5", "10.0.0.5"),
        ("::1", "::1"),
        ("fd00::42", "fd00::42"),
    ],
)
def test_ip_addresses_infer_without_dns(
    target: str, expected_ip: str, no_network: dict[str, Mock]
) -> None:
    kind, details = infer_target_type(target)

    assert kind == "ip_address"
    assert details == {"target_ip": expected_ip}
    _assert_no_http(no_network)
    no_network["dns"].assert_not_called()


def test_local_directory_infers_local_code(tmp_path: Path, no_network: dict[str, Mock]) -> None:
    kind, details = infer_target_type(str(tmp_path))

    assert kind == "local_code"
    assert details == {"target_path": str(tmp_path.resolve())}
    _assert_no_http(no_network)


def test_existing_file_is_not_a_local_code_target(
    tmp_path: Path, no_network: dict[str, Mock]
) -> None:
    file_path = tmp_path / "a-file.txt"
    file_path.write_text("x", encoding="utf-8")

    with pytest.raises(ValueError, match="not a directory"):
        infer_target_type(str(file_path))
    _assert_no_http(no_network)


@pytest.mark.parametrize(
    ("target", "expected_url"),
    [
        ("example.com", "https://example.com"),
        ("example.com/org/repo", "https://example.com/org/repo"),
    ],
)
def test_bare_hosts_default_to_web_application(
    target: str, expected_url: str, no_network: dict[str, Mock]
) -> None:
    kind, details = infer_target_type(target)

    assert kind == "web_application"
    assert details == {"target_url": expected_url}
    _assert_no_http(no_network)


def test_invalid_target_still_raises(no_network: dict[str, Mock]) -> None:
    with pytest.raises(ValueError, match="Invalid target"):
        infer_target_type("not-a-target")
    _assert_no_http(no_network)


# ---------------------------------------------------------------------------
# Explicit --target-type validation (kind must match input shape)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("target", "expected_repo"),
    [
        ("https://github.com/org/repo", "https://github.com/org/repo"),
        ("http://127.0.0.1:8443/org/repo", "http://127.0.0.1:8443/org/repo"),
        ("git@github.com:org/repo.git", "git@github.com:org/repo.git"),
        ("git://git.example.com/org/repo", "git://git.example.com/org/repo"),
        ("example.com/org/repo", "https://example.com/org/repo"),
    ],
)
def test_explicit_repository_accepts_remote_git_shapes(
    target: str, expected_repo: str, no_network: dict[str, Mock]
) -> None:
    kind, details = resolve_target_type(target, "repository")

    assert kind == "repository"
    assert details == {"target_repo": expected_repo}
    _assert_no_http(no_network)


@pytest.mark.parametrize(
    "target",
    [
        "example.com",
        "192.168.1.10",
        "ssh://git@github.com/org/repo.git",
    ],
)
def test_explicit_repository_rejects_non_repository_shapes(
    target: str, no_network: dict[str, Mock]
) -> None:
    with pytest.raises(ValueError, match="--target-type repository"):
        resolve_target_type(target, "repository")
    _assert_no_http(no_network)


def test_explicit_repository_rejects_local_directory(
    tmp_path: Path, no_network: dict[str, Mock]
) -> None:
    with pytest.raises(ValueError, match="--target-type local_code"):
        resolve_target_type(str(tmp_path), "repository")
    _assert_no_http(no_network)


@pytest.mark.parametrize(
    ("target", "expected_url"),
    [
        ("https://app.example.com", "https://app.example.com"),
        ("http://127.0.0.1:3000/app", "http://127.0.0.1:3000/app"),
        ("http://[fd00::1]/app", "http://[fd00::1]/app"),
        ("example.com", "https://example.com"),
        ("example.com/path", "https://example.com/path"),
    ],
)
def test_explicit_web_application_accepts_url_shapes(
    target: str, expected_url: str, no_network: dict[str, Mock]
) -> None:
    kind, details = resolve_target_type(target, "web_application")

    assert kind == "web_application"
    assert details == {"target_url": expected_url}
    _assert_no_http(no_network)


@pytest.mark.parametrize(
    "target",
    [
        "https://github.com/org/repo.git",
        "git@github.com:org/repo.git",
        "git://git.example.com/org/repo",
        "192.168.1.10",
        "ftp://example.com/pub",
    ],
)
def test_explicit_web_application_rejects_non_url_shapes(
    target: str, no_network: dict[str, Mock]
) -> None:
    with pytest.raises(ValueError, match="--target-type"):
        resolve_target_type(target, "web_application")
    _assert_no_http(no_network)


def test_explicit_web_application_does_not_bypass_url_credential_check(
    no_network: dict[str, Mock],
) -> None:
    with pytest.raises(ValueError, match="credential"):
        resolve_target_type("https://user:pass@example.com/app", "web_application")
    _assert_no_http(no_network)


def test_explicit_local_code_requires_existing_directory(
    tmp_path: Path, no_network: dict[str, Mock]
) -> None:
    kind, details = resolve_target_type(str(tmp_path), "local_code")

    assert kind == "local_code"
    assert details == {"target_path": str(tmp_path.resolve())}
    _assert_no_http(no_network)


@pytest.mark.parametrize(
    "target",
    [
        "https://github.com/org/repo",
        "git@github.com:org/repo.git",
        "192.168.1.10",
        "definitely/missing/path",
    ],
)
def test_explicit_local_code_rejects_non_local_shapes(
    target: str, no_network: dict[str, Mock]
) -> None:
    with pytest.raises(ValueError, match="--target-type local_code"):
        resolve_target_type(target, "local_code")
    _assert_no_http(no_network)


def test_explicit_local_code_rejects_files(tmp_path: Path, no_network: dict[str, Mock]) -> None:
    file_path = tmp_path / "a-file.txt"
    file_path.write_text("x", encoding="utf-8")

    with pytest.raises(ValueError, match="not a directory"):
        resolve_target_type(str(file_path), "local_code")
    _assert_no_http(no_network)


@pytest.mark.parametrize("target", ["10.0.0.5", "fd00::42"])
def test_explicit_ip_address_accepts_ip_literals(target: str, no_network: dict[str, Mock]) -> None:
    kind, details = resolve_target_type(target, "ip_address")

    assert kind == "ip_address"
    assert details == {"target_ip": target}
    _assert_no_http(no_network)


@pytest.mark.parametrize("target", ["https://10.0.0.5/app", "example.com", "not-an-ip"])
def test_explicit_ip_address_rejects_non_ip_shapes(
    target: str, no_network: dict[str, Mock]
) -> None:
    with pytest.raises(ValueError, match="--target-type ip_address"):
        resolve_target_type(target, "ip_address")
    _assert_no_http(no_network)


def test_unknown_explicit_kind_rejected(no_network: dict[str, Mock]) -> None:
    with pytest.raises(ValueError, match="Unknown --target-type"):
        resolve_target_type("https://example.com", "ssh_config")
    _assert_no_http(no_network)


def test_omitted_kind_falls_back_to_offline_inference(no_network: dict[str, Mock]) -> None:
    kind, details = resolve_target_type("git@github.com:org/repo.git", None)

    assert kind == "repository"
    assert details == {"target_repo": "git@github.com:org/repo.git"}
    _assert_no_http(no_network)


# ---------------------------------------------------------------------------
# CLI wiring
# ---------------------------------------------------------------------------


def test_help_lists_target_type_flag(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "argv", ["lyrashield", "--help"])

    with pytest.raises(SystemExit) as exc_info:
        cli_main.parse_arguments()

    assert exc_info.value.code == 0
    assert "--target-type" in capsys.readouterr().out


def test_target_type_repository_marks_ambiguous_url_as_repository(
    monkeypatch: pytest.MonkeyPatch, no_network: dict[str, Mock]
) -> None:
    args = _parse(
        monkeypatch,
        ["-t", "https://github.com/org/repo", "--target-type", "repository", "-n"],
    )

    assert args.targets_info[0]["type"] == "repository"
    assert args.targets_info[0]["details"]["target_repo"] == "https://github.com/org/repo"
    _assert_no_http(no_network)


def test_target_type_mismatch_errors_actionably(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    no_network: dict[str, Mock],
) -> None:
    with pytest.raises(SystemExit) as exc_info:
        _parse(
            monkeypatch,
            ["-t", "https://github.com/org/repo.git", "--target-type", "web_application", "-n"],
        )

    assert exc_info.value.code == 2
    err = capsys.readouterr().err
    assert "--target-type repository" in err
    _assert_no_http(no_network)


def test_target_type_invalid_choice_errors(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as exc_info:
        _parse(monkeypatch, ["-t", "https://example.com", "--target-type", "api_spec", "-n"])

    assert exc_info.value.code == 2
    assert "invalid choice" in capsys.readouterr().err


def test_target_type_requires_targets(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    with pytest.raises(SystemExit) as exc_info:
        _parse(
            monkeypatch,
            ["--mount", str(tmp_path), "--target-type", "repository", "-n"],
        )

    assert exc_info.value.code == 2
    assert "--target-type" in capsys.readouterr().err


def test_target_type_rejects_resume(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as exc_info:
        _parse(monkeypatch, ["--resume", "old-run", "--target-type", "repository"])

    assert exc_info.value.code == 2
    assert "--target-type" in capsys.readouterr().err


def test_target_type_applies_to_target_list_entries(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    no_network: dict[str, Mock],
) -> None:
    target_list = tmp_path / "targets.txt"
    target_list.write_text(
        "https://github.com/org/one\ngit@github.com:org/two.git\n", encoding="utf-8"
    )

    args = _parse(
        monkeypatch,
        ["--target-list", str(target_list), "--target-type", "repository", "-n"],
    )

    assert [t["type"] for t in args.targets_info] == ["repository", "repository"]
    _assert_no_http(no_network)


def test_explicit_flag_is_not_authorization_for_private_fetch(
    monkeypatch: pytest.MonkeyPatch, no_network: dict[str, Mock]
) -> None:
    # Classification records the kind only: a private-address repository target
    # produces the same target dict as any other repository — the fetch still
    # goes through the existing guarded clone path, never inference-time HTTP.
    args = _parse(
        monkeypatch,
        ["-t", "http://192.168.1.20/internal/repo", "--target-type", "repository", "-n"],
    )

    entry = args.targets_info[0]
    assert entry["type"] == "repository"
    assert entry["details"]["target_repo"] == "http://192.168.1.20/internal/repo"
    assert "cloned_repo_path" not in entry["details"]
    _assert_no_http(no_network)
    no_network["dns"].assert_not_called()


def test_explicit_repository_still_routes_through_guarded_clone() -> None:
    # Approved acquisition stays on the existing clone_repository path; the flag
    # must not create a second unchecked fetch path.
    assert interface_utils.clone_repository is cli_main.clone_repository
