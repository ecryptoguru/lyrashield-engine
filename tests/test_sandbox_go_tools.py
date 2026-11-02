"""Security build contracts for the actual Go executables shipped by the sandbox."""

import os
import re
import shlex
import subprocess
from pathlib import Path


ROOT = Path(__file__).parents[1]
INPUTS = ROOT / "containers" / "go-tools"


def test_go_tools_preserve_all_pinned_upstream_sources_and_release_settings() -> None:
    rows = [
        line.split("|")
        for line in (INPUTS / "sources.tsv").read_text().splitlines()
        if line and not line.startswith("#")
    ]
    assert {row[0] for row in rows} == {
        "httpx",
        "katana",
        "gospider",
        "interactsh-client",
        "vulnx",
        "gitleaks",
        "trivy",
        "trufflehog",
    }
    for name, _repo, commit, checksum, _package, tags, experiment, _version in rows:
        assert re.fullmatch("[0-9a-f]{40}", commit)
        assert re.fullmatch("[0-9a-f]{64}", checksum)
        assert (INPUTS / name / "go.mod").is_file()
        assert (INPUTS / name / "go.sum").is_file()
        if name == "gitleaks":
            assert tags == "gore2regex"
        if name == "trivy":
            assert experiment == "jsonv2"


def test_go_build_uses_locked_graph_and_keeps_binaries_auditable() -> None:
    script = (INPUTS / "build.sh").read_text()
    assert "-mod=readonly" in script
    assert "GOTOOLCHAIN=local GOSUMDB=sum.golang.org" in script
    assert "sha256sum -c -" in script
    assert "go mod verify" in script
    assert "go version -m" in script
    assert "cp go.mod go.sum" in script
    assert "LICENSE LICENSE.txt LICENSE.md COPYING NOTICE" in script
    assert '"$provenance/source.txt"' in script
    assert "go get" not in script
    assert "upx" not in script
    dockerfile = (ROOT / "containers" / "Dockerfile").read_text()
    assert "ARG GO_VERSION=1.27.3" in dockerfile
    assert "containers/go-tools/" in dockerfile
    assert "/out/share/go-tools/ /usr/local/share/lyrashield/go-tools/" in dockerfile
    assert "go install" not in dockerfile


def test_security_dependency_floors_are_locked_per_existing_tool_graph() -> None:
    tools = ("gospider", "httpx", "katana", "interactsh-client", "vulnx", "trivy", "trufflehog")
    for name in tools:
        graph = (INPUTS / name / "go.mod").read_text()
        assert "golang.org/x/net v0.62.0" in graph
        assert "golang.org/x/crypto v0.58.0" in graph
        assert "golang.org/x/text v0.43.0" in graph
    assert "github.com/jackc/pgx/v5 v5.12.0" in (INPUTS / "katana" / "go.mod").read_text()
    for name in ("trivy", "trufflehog"):
        assert "github.com/go-jose/go-jose/v4 v4.1.6" in (INPUTS / name / "go.mod").read_text()
    gitleaks = (INPUTS / "gitleaks" / "go.mod").read_text()
    assert "github.com/mholt/archives v0.1.2" in gitleaks
    assert "github.com/nwaples/rardecode/v2 v2.2.1" in gitleaks
    for name in ("httpx", "katana", "interactsh-client", "vulnx", "trufflehog"):
        assert "github.com/yuin/goldmark v1.7.17" in (INPUTS / name / "go.mod").read_text()
    trufflehog = (INPUTS / "trufflehog" / "go.mod").read_text()
    assert (
        "replace github.com/jpillora/overseer => github.com/trufflesecurity/overseer v1.2.8"
        in trufflehog
    )
    assert (
        "replace github.com/coinbase/waas-client-library-go => "
        "github.com/trufflesecurity/waas-client-library-go v1.0.9" in trufflehog
    )


def test_go_build_rejects_tampered_source_before_extraction(tmp_path, monkeypatch) -> None:
    commands = tmp_path / "commands"
    commands.mkdir()
    marker = tmp_path / "extracted"
    fakes = {
        "go": "#!/bin/sh\nprintf 'go1.27.3\\n'\n",
        "curl": '#!/bin/sh\nwhile [ "$1" != "-o" ]; do shift; done\nprintf tampered > "$2"\n',
        "tar": f"#!/bin/sh\ntouch {shlex.quote(str(marker))}\n",
    }
    for name, content in fakes.items():
        executable = commands / name
        executable.write_text(content)
        executable.chmod(0o755)
    monkeypatch.setenv("PATH", str(commands) + os.pathsep + os.environ["PATH"])
    result = subprocess.run(  # noqa: S603 - fixed local test script
        ["/bin/sh", str(INPUTS / "build.sh"), str(tmp_path / "output")],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert "FAILED" in result.stdout or "mismatch" in result.stderr.lower()
    assert not marker.exists()
