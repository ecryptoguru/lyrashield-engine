"""Supply-chain invariants for the sandbox image definition."""

from __future__ import annotations

from pathlib import Path


DOCKERFILE = Path(__file__).parents[1] / "containers" / "Dockerfile"
DOCKERIGNORE = Path(__file__).parents[1] / ".dockerignore"


def test_gitleaks_install_is_version_and_checksum_pinned() -> None:
    content = DOCKERFILE.read_text(encoding="utf-8")

    assert "ARG GITLEAKS_VERSION=" in content
    assert "ARG GITLEAKS_LINUX_X64_SHA256=" in content
    assert "ARG GITLEAKS_LINUX_ARM64_SHA256=" in content
    assert "sha256sum -c -" in content
    assert "api.github.com/repos/gitleaks/gitleaks/releases/latest" not in content


def test_every_external_sandbox_input_is_immutable_or_hash_verified() -> None:
    content = DOCKERFILE.read_text(encoding="utf-8")

    assert "FROM kalilinux/kali-rolling@sha256:" in content
    assert "ARG KALI_APT_SUITE=kali-last-snapshot" in content
    assert "ARG KALI_APT_INRELEASE_SHA256=" in content
    assert "Pin-Priority: 1001" in content
    assert "apt-get full-upgrade -y" in content
    assert "archive.kali.org/kali" in content
    assert "@latest" not in content
    assert "curl -LsSf https://astral.sh/uv/install.sh" not in content
    assert "trufflehog/main/scripts/install.sh" not in content
    assert "trivy/main/contrib/install.sh" not in content
    assert "nuclei -update-templates" not in content
    assert 'git clone --depth 1 "${repo_url}"' not in content
    assert "ARG TRUFFLEHOG_VERSION=" in content
    assert "ARG TRIVY_VERSION=" in content
    assert "ARG CAIDO_LINUX_X64_SHA256=" in content
    assert "ARG CAIDO_LINUX_ARM64_SHA256=" in content
    assert "--require-hashes" in content
    assert "containers/python-requirements.txt" in content
    assert "npm ci --omit=dev" in content
    assert "npm install -g" not in content


def test_nmap_file_capabilities_work_without_opt_in_net_admin() -> None:
    content = DOCKERFILE.read_text(encoding="utf-8")

    assert "setcap cap_net_raw,cap_net_bind_service+eip /usr/lib/nmap/nmap" in content
    assert "setcap cap_net_raw,cap_net_admin" not in content


def test_wapiti_install_refreshes_rolling_package_index() -> None:
    content = DOCKERFILE.read_text(encoding="utf-8")

    install = "apt-get install -y --no-install-recommends wapiti"
    assert "RUN apt-get update" in content
    assert install in content


def test_engine_build_context_excludes_tests_and_frontend_source() -> None:
    ignored = set(DOCKERIGNORE.read_text(encoding="utf-8").splitlines())

    assert "tests" in ignored
    assert "**/interface/viewer/frontend" in ignored
