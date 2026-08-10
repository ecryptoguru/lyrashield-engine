"""Tests for sandbox image digest verification in strix/interface/main.py."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from lyrashield.interface.main import _normalize_digest, _verify_image_digest


VALID_DIGEST = "a" * 64
OTHER_DIGEST = "b" * 64


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("sha256:abc123", "abc123"),
        ("SHA256:ABC123", "abc123"),
        ("repo/image@sha256:abc123", "abc123"),
        ("abc123", "abc123"),
    ],
)
def test_normalize_digest_strips_prefixes(value: str, expected: str) -> None:
    assert _normalize_digest(value) == expected


def _client_with_digests(digests: list[str]) -> MagicMock:
    client = MagicMock()
    image = SimpleNamespace(attrs={"RepoDigests": digests})
    client.images.get.return_value = image
    return client


def test_verify_image_digest_passes_when_digest_matches() -> None:
    client = _client_with_digests([f"repo/image@sha256:{VALID_DIGEST}"])
    _verify_image_digest(client, "repo/image:tag", f"sha256:{VALID_DIGEST}")


def test_verify_image_digest_passes_with_bare_hex() -> None:
    client = _client_with_digests([f"repo/image@sha256:{VALID_DIGEST}"])
    _verify_image_digest(client, "repo/image:tag", VALID_DIGEST.upper())


def test_verify_image_digest_fails_when_no_digests_match() -> None:
    client = _client_with_digests([f"repo/image@sha256:{OTHER_DIGEST}"])
    with pytest.raises(RuntimeError, match="digest verification failed"):
        _verify_image_digest(client, "repo/image:tag", f"sha256:{VALID_DIGEST}")


def test_verify_image_digest_fails_when_repo_digests_empty() -> None:
    client = _client_with_digests([])
    with pytest.raises(RuntimeError, match="digest verification failed"):
        _verify_image_digest(client, "repo/image:tag", f"sha256:{VALID_DIGEST}")


def test_verify_image_digest_rejects_empty_expected() -> None:
    client = _client_with_digests([f"repo/image@sha256:{VALID_DIGEST}"])
    with pytest.raises(RuntimeError, match="empty or malformed"):
        _verify_image_digest(client, "repo/image:tag", " ")


def test_verify_image_digest_rejects_malformed_expected() -> None:
    client = _client_with_digests([f"repo/image@sha256:{VALID_DIGEST}"])
    with pytest.raises(RuntimeError, match="not a 64-character"):
        _verify_image_digest(client, "repo/image:tag", "sha256:abc123")
