"""Supply-chain invariants for the sandbox image definition."""

from __future__ import annotations

from pathlib import Path


DOCKERFILE = Path(__file__).parents[1] / "containers" / "Dockerfile"


def test_gitleaks_install_is_version_and_checksum_pinned() -> None:
    content = DOCKERFILE.read_text(encoding="utf-8")

    assert "ARG GITLEAKS_VERSION=" in content
    assert "ARG GITLEAKS_LINUX_X64_SHA256=" in content
    assert "ARG GITLEAKS_LINUX_ARM64_SHA256=" in content
    assert "sha256sum -c -" in content
    assert "api.github.com/repos/gitleaks/gitleaks/releases/latest" not in content
