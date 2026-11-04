import copy
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest


SOURCE = Path(__file__).parents[1] / "scripts" / "check_go_sbom_coverage.py"
spec = importlib.util.spec_from_file_location("check_go_sbom_coverage", SOURCE)
oracle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oracle)


def build_info():
    return {
        "GoVersion": "go1.26.5",
        "Path": "example.test/app/cmd",
        "Main": {"Path": "example.test/app", "Version": "(devel)"},
        "Deps": [
            {"Path": "example.test/a", "Version": "v1.2.3"},
            {"Path": "example.test/b", "Version": "v0.1.0+incompatible"},
        ],
        "Settings": [{"Key": "GOOS", "Value": "linux"}, {"Key": "GOARCH", "Value": "amd64"}],
    }


def package(name, version, purl):
    return {
        "name": name,
        "versionInfo": version,
        "externalRefs": [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": purl,
            }
        ],
    }


def sbom():
    return {
        "spdxVersion": "SPDX-2.3",
        "packages": [
            package("example.test/a", "v1.2.3", "pkg:golang/example.test/a@v1.2.3"),
            package(
                "example.test/b",
                "v0.1.0+incompatible",
                "pkg:golang/example.test/b@v0.1.0%2Bincompatible",
            ),
        ],
    }


def test_compares_embedded_versioned_dependencies_against_spdx_purls():
    result = oracle.compare_go_dependencies(build_info(), sbom(), "amd64")
    assert result["dependency_count"] == 2
    assert result["matched_count"] == 2


def test_supported_intoto_wrapper_is_only_unverified_container():
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "predicateType": "https://spdx.dev/Document",
        "predicate": sbom(),
    }
    assert oracle.compare_go_dependencies(build_info(), statement, "amd64")["matched_count"] == 2
    statement["predicateType"] = "https://example.test/other"
    with pytest.raises(ValueError):
        oracle.compare_go_dependencies(build_info(), statement, "amd64")


@pytest.mark.parametrize(
    "mutation", ["missing", "wrong-name", "wrong-version", "wrong-type", "wrong-category"]
)
def test_missing_or_spoofed_purl_cannot_satisfy_dependency(mutation):
    document = sbom()
    if mutation == "missing":
        document["packages"].pop()
    else:
        item = document["packages"][1]
        if mutation == "wrong-name":
            item["name"] = "foreign"
        elif mutation == "wrong-version":
            item["versionInfo"] = "v0.2.0"
        elif mutation == "wrong-type":
            item["externalRefs"][0]["referenceLocator"] = item["externalRefs"][0][
                "referenceLocator"
            ].replace("golang/", "npm/")
        else:
            item["externalRefs"][0]["referenceCategory"] = "OTHER"
    with pytest.raises(ValueError):
        oracle.compare_go_dependencies(build_info(), document, "amd64")


def test_replacement_is_compared_as_compiled_module_not_original():
    info = build_info()
    info["Deps"][0]["Replace"] = {"Path": "example.test/fork", "Version": "v1.4.0"}
    document = sbom()
    with pytest.raises(ValueError):
        oracle.compare_go_dependencies(info, document, "amd64")
    document["packages"][0] = package(
        "example.test/fork", "v1.4.0", "pkg:golang/example.test/fork@v1.4.0"
    )
    assert oracle.compare_go_dependencies(info, document, "amd64")["matched_count"] == 2


@pytest.mark.parametrize(
    "mutation", ["duplicate-original", "duplicate-effective", "nested-replacement"]
)
def test_ambiguous_dependency_graph_fails_closed(mutation):
    info = build_info()
    if mutation == "duplicate-original":
        info["Deps"].append(copy.deepcopy(info["Deps"][0]))
    elif mutation == "duplicate-effective":
        info["Deps"][1]["Replace"] = copy.deepcopy(info["Deps"][0])
    else:
        info["Deps"][0]["Replace"] = {
            "Path": "example.test/fork",
            "Version": "v1.2.3",
            "Replace": {"Path": "example.test/other", "Version": "v1.2.3"},
        }
    with pytest.raises(ValueError):
        oracle.compare_go_dependencies(info, sbom(), "amd64")


@pytest.mark.parametrize(
    "mutation",
    [
        "empty",
        "local",
        "missing-version",
        "wrong-arch",
        "duplicate-arch",
        "wrong-os",
        "invalid-spdx",
    ],
)
def test_unknown_or_invalid_input_never_counts_as_coverage(mutation):
    info, document = build_info(), sbom()
    if mutation == "empty":
        info["Deps"] = []
    elif mutation == "local":
        info["Deps"][0]["Replace"] = {"Path": "../local", "Version": "(devel)"}
    elif mutation == "missing-version":
        del info["Deps"][0]["Version"]
    elif mutation == "wrong-arch":
        info["Settings"][1]["Value"] = "arm64"
    elif mutation == "duplicate-arch":
        info["Settings"].append(copy.deepcopy(info["Settings"][1]))
    elif mutation == "wrong-os":
        info["Settings"][0]["Value"] = "darwin"
    else:
        document["spdxVersion"] = "unknown"
    with pytest.raises(ValueError):
        oracle.compare_go_dependencies(info, document, "amd64")


@pytest.fixture(scope="module")
def compiled_go_fixture(tmp_path_factory):
    go = shutil.which("go")
    if not go:
        pytest.skip("Go toolchain unavailable")
    root = tmp_path_factory.mktemp("go-sbom-fixture")
    (root / "vendor" / "example.test" / "dep").mkdir(parents=True)
    (root / "go.mod").write_text(
        "module example.test/app\ngo 1.20\nrequire example.test/dep v1.2.3\n"
    )
    (root / "main.go").write_text(
        'package main\nimport("example.test/dep";"os")\nfunc main(){dep.Run();os.WriteFile('
        + json.dumps(str(root / "executed"))
        + ',[]byte("run"),0600)}\n'
    )
    (root / "vendor" / "modules.txt").write_text(
        "# example.test/dep v1.2.3\n## explicit; go 1.20\nexample.test/dep\n"
    )
    (root / "vendor" / "example.test" / "dep" / "dep.go").write_text("package dep\nfunc Run() {}\n")
    env = {
        "PATH": os.environ["PATH"],
        "HOME": str(root),
        "GOCACHE": str(root / "cache"),
        "GOTOOLCHAIN": "local",
        "GOPROXY": "off",
        "GOSUMDB": "off",
        "GOENV": "off",
        "GOWORK": "off",
        "GOOS": "linux",
        "GOARCH": "amd64",
        "CGO_ENABLED": "0",
    }
    binary = root / "app"
    subprocess.run(  # noqa: S603 - local Go compiler, fixed fixture and network-disabled environment
        [go, "build", "-mod=vendor", "-o", str(binary), "."],
        cwd=root,
        env=env,
        timeout=90,
        check=True,
    )
    return root, Path(go), binary


def test_cli_reads_real_linux_go_binary_without_running_it(compiled_go_fixture):
    root, go, binary = compiled_go_fixture
    doc = {
        "spdxVersion": "SPDX-2.3",
        "packages": [package("example.test/dep", "v1.2.3", "pkg:golang/example.test/dep@v1.2.3")],
    }
    spdx = root / "sbom.json"
    spdx.write_text(json.dumps(doc))
    command = [
        sys.executable,
        str(SOURCE),
        "--binary",
        str(binary),
        "--spdx",
        str(spdx),
        "--architecture",
        "amd64",
        "--go",
        str(go),
    ]
    result = subprocess.run(command, capture_output=True, text=True, timeout=45, check=False)  # noqa: S603
    assert result.returncode == 0, result.stderr
    receipt = json.loads(result.stdout)
    assert receipt["scope"] == "versioned-go-dependencies-only"
    assert receipt["dependency_count"] == 1
    assert receipt["binary_sha256"] == hashlib.sha256(binary.read_bytes()).hexdigest()
    assert receipt["spdx_sha256"] == hashlib.sha256(spdx.read_bytes()).hexdigest()
    assert receipt["go_tool_sha256"] == hashlib.sha256(go.read_bytes()).hexdigest()
    assert not (root / "executed").exists()
    doc["packages"] = []
    spdx.write_text(json.dumps(doc))
    result = subprocess.run(command, capture_output=True, text=True, timeout=45, check=False)  # noqa: S603
    assert result.returncode != 0
    assert not result.stdout


def test_cli_rejects_wrong_architecture_and_non_go_binary(compiled_go_fixture):
    root, go, binary = compiled_go_fixture
    with pytest.raises(ValueError):
        oracle.inspect_binary(binary, go, "arm64")
    fake = root / "fake"
    fake.write_bytes(b"\x7fELF\x02\x01" + b"\x00" * 10 + b"\x02\x00\x3e\x00" + b"\x00" * 30)
    with pytest.raises(subprocess.SubprocessError):
        oracle.inspect_binary(fake, go, "amd64")


def test_inputs_reject_symlinks_and_non_regular_files(compiled_go_fixture):
    root, go, binary = compiled_go_fixture
    link = root / "binary-link"
    link.symlink_to(binary)
    with pytest.raises(OSError):
        oracle.inspect_binary(link, go, "amd64")
    with pytest.raises(ValueError):
        oracle.read_bounded(root, oracle.MAX_SBOM)
    sbom_link = root / "sbom-link"
    sbom_link.symlink_to(binary)
    with pytest.raises(OSError):
        oracle.read_bounded(sbom_link, oracle.MAX_SBOM)
    fifo = root / "input-pipe"
    os.mkfifo(fifo)
    with pytest.raises(ValueError):
        oracle.inspect_binary(fifo, go, "amd64")


def test_duplicate_json_keys_fail_closed():
    with pytest.raises(ValueError):
        json.loads('{"Deps":[],"Deps":[1]}', object_pairs_hook=oracle.unique_pairs)
