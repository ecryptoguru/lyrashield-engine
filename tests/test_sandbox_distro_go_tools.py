"""Contracts for the signed Kali Go application rebuild."""

import json
import os
import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INPUTS = ROOT / "containers/go-tools/distro"


def test_source_manifest_covers_binary_and_source_archives_for_both_architectures() -> None:
    versions = {
        "ffuf": "2.2.1-1",
        "naabu": "2.6.1-0kali1",
        "nuclei": "3.11.1-0kali1",
        "subfinder": "2.16.0-0kali1",
    }
    rows = [
        line.split("|")
        for line in (INPUTS / "sources.tsv").read_text().splitlines()
        if not line.startswith("#")
    ]
    assert len(rows) == len(versions)
    assert {name: version for name, version, *_ in rows} == versions
    supplement = json.loads((INPUTS / "applications.cdx.json").read_text())
    components = {c["name"]: c for c in supplement["components"]}
    assert len(components) == len(rows) == len(supplement["components"])
    for name, distro_version, *digests in rows:
        assert len(digests) == 5
        assert all(re.fullmatch(r"[0-9a-f]{64}", digest) for digest in digests)
        assert len(set(digests)) == 5
        graph = (INPUTS / name / "go.mod").read_text()
        module = graph.splitlines()[0].split()[1]
        component = components[module]
        version = "v" + distro_version.rsplit("-", 1)[0]
        assert component["version"] == version
        assert component["purl"] == f"pkg:golang/{module}@{version}"
        properties = {p["name"]: p["value"] for p in component["properties"]}
        assert properties["lyrashield:kali:source-descriptor-sha256"] == digests[0]
        assert properties["lyrashield:kali:orig-tar-sha256"] == digests[1]
        assert re.fullmatch(r"[0-9a-f]{40}", properties["lyrashield:upstream:commit"])
        assert "golang.org/x/net v0.62.0" in graph
        assert len((INPUTS / name / "go.sum").read_text().splitlines()) > 8
    assert (
        "replace github.com/google/go-github/v30 => github.com/google/go-github/v51 v51.0.0"
        in (INPUTS / "nuclei/go.mod").read_text()
    )


def test_build_stops_before_extraction_on_bad_source(tmp_path: Path) -> None:
    # Exercise the production entrypoint before it can reach extraction or compilation.
    for name, body in {
        "dpkg": "echo arm64",
        "go": 'test "$*" = "env GOVERSION" && echo go1.27.3',
        "curl": 'for last do :; done; printf corrupt > "$last"',
        "sha256sum": 'exec shasum -a 256 "$@"'
        if not Path("/usr/bin/sha256sum").exists()
        else 'exec /usr/bin/sha256sum "$@"',
    }.items():
        stub = tmp_path / name
        stub.write_text("#!/bin/sh\n" + body + "\n")
        stub.chmod(0o755)
    result = subprocess.run(  # noqa: S603 - fixed local script
        ["/bin/sh", str(INPUTS / "build.sh"), str(tmp_path / "out")],
        env={**os.environ, "PATH": f"{tmp_path}:{os.environ['PATH']}"},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert "FAILED" in result.stdout + result.stderr
    assert not list((tmp_path / "out").iterdir())


def test_runtime_installs_rebuilt_packages_and_discards_combined_builder_cache() -> None:
    dockerfile = (ROOT / "containers/Dockerfile").read_text().replace("\\\n", " ")
    build = next(line for line in dockerfile.splitlines() if line.startswith("RUN export GOPATH="))
    assert (
        build.index("go-tools/build.sh")
        < build.index("go-tools/distro/build.sh")
        < build.index("rm -rf /tmp/lyrashield-go-cache")
    )
    assert "GOCACHE=/tmp/lyrashield-go-cache/build" in build
    install = next(
        line for line in dockerfile.splitlines() if "from=gobuilder,source=/out/distro" in line
    )
    assert "libpcap0.8t64=1.10.6-2 /tmp/distro-go-debs/*.deb" in install
    assert "sqlmap nuclei subfinder naabu ffuf" not in dockerfile
    assert "verify_distro_go_tools.py" in (ROOT / "scripts/smoke-sandbox.sh").read_text()
