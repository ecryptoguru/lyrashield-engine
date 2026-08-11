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


def test_nmap_file_capabilities_work_without_opt_in_net_admin() -> None:
    content = DOCKERFILE.read_text(encoding="utf-8")

    assert "setcap cap_net_raw,cap_net_bind_service+eip /usr/lib/nmap/nmap" in content
    assert "setcap cap_net_raw,cap_net_admin" not in content


def test_wapiti_install_refreshes_rolling_package_index() -> None:
    content = DOCKERFILE.read_text(encoding="utf-8")

    install = "apt-get install -y --no-install-recommends wapiti"
    assert "RUN apt-get update" in content
    assert install in content
