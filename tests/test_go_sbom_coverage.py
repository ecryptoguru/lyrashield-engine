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
        "SPDXID": "SPDXRef-" + hashlib.sha256(f"{name}@{version}".encode()).hexdigest(),
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
        "SPDXID": "SPDXRef-DOCUMENT",
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


def test_diagnostic_distinguishes_exact_match_absent_and_duplicate_candidates():
    info = build_info()
    info["Deps"].append({"Path": "example.test/c", "Version": "v2.0.0"})
    document = sbom()
    document["packages"].pop()
    duplicate = copy.deepcopy(document["packages"][0])
    duplicate["SPDXID"] = "SPDXRef-another-instance"
    document["packages"].append(duplicate)
    document["packages"].append(
        package("example.test/c", "v2.0.0", "pkg:golang/example.test/c@v2.0.0")
    )

    result = oracle.diagnose_go_dependencies(info, document, "amd64")
    assert result == [
        {
            "name": "example.test/a",
            "version": "v1.2.3",
            "state": "ambiguous",
            "candidates": 2,
            "unversioned_candidates": 0,
        },
        {
            "name": "example.test/b",
            "version": "v0.1.0+incompatible",
            "state": "absent-but-unresolved",
            "candidates": 0,
            "unversioned_candidates": 0,
        },
        {
            "name": "example.test/c",
            "version": "v2.0.0",
            "state": "matched",
            "candidates": 1,
            "unversioned_candidates": 0,
        },
    ]
    with pytest.raises(ValueError):
        oracle.compare_go_dependencies(info, document, "amd64")


def test_diagnostic_matches_the_effective_replacement_not_original_module():
    info = build_info()
    info["Deps"][0]["Replace"] = {"Path": "example.test/fork", "Version": "v1.4.0"}
    result = oracle.diagnose_go_dependencies(info, sbom(), "amd64")
    assert result == [
        {
            "name": "example.test/b",
            "version": "v0.1.0+incompatible",
            "state": "matched",
            "candidates": 1,
            "unversioned_candidates": 0,
        },
        {
            "name": "example.test/fork",
            "version": "v1.4.0",
            "state": "absent-but-unresolved",
            "candidates": 0,
            "unversioned_candidates": 0,
        },
    ]


def test_unversioned_same_name_makes_even_an_exact_match_ambiguous():
    document = sbom()
    unknown = package("example.test/a", "UNKNOWN", "pkg:golang/example.test/a")
    unknown["SPDXID"] = "SPDXRef-unknown-version"
    document["packages"].append(unknown)
    result = oracle.diagnose_go_dependencies(build_info(), document, "amd64")
    assert result[0] == {
        "name": "example.test/a",
        "version": "v1.2.3",
        "state": "ambiguous",
        "candidates": 1,
        "unversioned_candidates": 1,
    }
    with pytest.raises(ValueError):
        oracle.compare_go_dependencies(build_info(), document, "amd64")


def test_unversioned_same_name_without_exact_candidate_is_not_absence():
    document = sbom()
    document["packages"].pop(0)
    unknown = package("example.test/a", "UNKNOWN", "pkg:golang/example.test/a")
    unknown["SPDXID"] = "SPDXRef-unknown-version"
    document["packages"].append(unknown)
    result = oracle.diagnose_go_dependencies(build_info(), document, "amd64")
    assert result[0]["state"] == "ambiguous"
    assert result[0]["candidates"] == 0
    assert result[0]["unversioned_candidates"] == 1


def test_unrelated_unversioned_modules_and_go_stdlib_do_not_hide_exact_matches():
    document = sbom()
    unknown = package("example.test/other", "UNKNOWN", "pkg:golang/example.test/other")
    unknown["SPDXID"] = "SPDXRef-unknown-version"
    stdlib = package("stdlib", "go1.27.3", "pkg:golang/stdlib@1.27.3")
    document["packages"].extend([unknown, stdlib])
    result = oracle.diagnose_go_dependencies(build_info(), document, "amd64")
    assert [entry["state"] for entry in result] == ["matched", "matched"]
    with pytest.raises(ValueError):
        oracle.compare_go_dependencies(build_info(), document, "amd64")


@pytest.mark.parametrize("kind", ["unversioned", "stdlib"])
def test_diagnostic_rejects_spoofed_unversioned_or_stdlib_purl(kind):
    document = sbom()
    if kind == "unversioned":
        item = package("example.test/other", "UNKNOWN", "pkg:golang/example.test/different")
    else:
        item = package("stdlib", "go1.27.3", "pkg:golang/stdlib@1.27.4")
    item["SPDXID"] = "SPDXRef-spoofed"
    document["packages"].append(item)
    with pytest.raises(ValueError):
        oracle.diagnose_go_dependencies(build_info(), document, "amd64")


@pytest.mark.parametrize(
    "mutation", ["unversioned-replacement", "duplicate-module", "bad-spdx-id", "bad-reference"]
)
def test_diagnostic_refuses_ambiguous_inputs_without_partial_matches(mutation):
    info, document = build_info(), sbom()
    if mutation == "unversioned-replacement":
        info["Deps"][0]["Replace"] = {"Path": "../local", "Version": "(devel)"}
    elif mutation == "duplicate-module":
        info["Deps"].append(copy.deepcopy(info["Deps"][0]))
    elif mutation == "bad-spdx-id":
        del document["packages"][1]["SPDXID"]
    else:
        document["packages"][1]["externalRefs"].append({"referenceType": "purl"})
    with pytest.raises((ValueError, TypeError)):
        oracle.diagnose_go_dependencies(info, document, "amd64")


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
        "missing-document-id",
        "missing-package-id",
        "duplicate-id",
        "ambiguous-purl",
        "malformed-reference",
        "conflicting-purl",
    ],
)
def test_malformed_or_ambiguous_spdx_never_counts_as_coverage(mutation):
    document = sbom()
    if mutation == "missing-document-id":
        del document["SPDXID"]
    elif mutation == "missing-package-id":
        del document["packages"][0]["SPDXID"]
    elif mutation == "duplicate-id":
        document["packages"][1]["SPDXID"] = document["packages"][0]["SPDXID"]
    elif mutation == "ambiguous-purl":
        duplicate = copy.deepcopy(document["packages"][0])
        duplicate["SPDXID"] = "SPDXRef-other-instance"
        document["packages"].append(duplicate)
    elif mutation == "malformed-reference":
        document["packages"][0]["externalRefs"].append({"referenceType": "purl"})
    else:
        conflicting = copy.deepcopy(document["packages"][0]["externalRefs"][0])
        conflicting["referenceLocator"] = "pkg:golang/example.test/foreign@v1.2.3"
        document["packages"][0]["externalRefs"].append(conflicting)
    with pytest.raises(ValueError):
        oracle.compare_go_dependencies(build_info(), document, "amd64")


@pytest.mark.parametrize("control", ["\x00", "\n", "\x7f", "\x85"])
@pytest.mark.parametrize("field", ["referenceCategory", "referenceType", "referenceLocator"])
def test_control_characters_in_even_unrelated_references_are_rejected(control, field):
    document = sbom()
    document["packages"].append(
        {
            "SPDXID": "SPDXRef-other-package",
            "name": "other",
            "versionInfo": "1",
            "externalRefs": [
                {
                    "referenceCategory": "OTHER",
                    "referenceType": "other",
                    "referenceLocator": "example.test/other",
                }
            ],
        }
    )
    document["packages"][-1]["externalRefs"][0][field] += control
    with pytest.raises(ValueError):
        oracle.compare_go_dependencies(build_info(), document, "amd64")


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
        "SPDXID": "SPDXRef-DOCUMENT",
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
    assert receipt["scope"] == "embedded-versioned-go-dependencies-only"
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


@pytest.mark.parametrize("state", ["matched", "absent-but-unresolved", "ambiguous"])
def test_cli_diagnostic_preserves_unresolved_states(compiled_go_fixture, state):
    root, go, binary = compiled_go_fixture
    entry = package("example.test/dep", "v1.2.3", "pkg:golang/example.test/dep@v1.2.3")
    packages = [] if state == "absent-but-unresolved" else [entry]
    if state == "ambiguous":
        duplicate = copy.deepcopy(entry)
        duplicate["SPDXID"] = "SPDXRef-another-instance"
        packages.append(duplicate)
    document = {"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "packages": packages}
    spdx = root / "diagnostic-sbom.json"
    spdx.write_text(json.dumps(document))
    result = subprocess.run(  # noqa: S603 - local offline fixture and trusted test Go tool
        [
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
            "--diagnostic",
        ],
        capture_output=True,
        text=True,
        timeout=45,
        check=False,
    )
    assert result.returncode == (0 if state == "matched" else 1), result.stderr
    receipt = json.loads(result.stdout)
    assert receipt["status"] == "diagnostic-only"
    assert receipt["dependencies"] == [
        {
            "name": "example.test/dep",
            "version": "v1.2.3",
            "state": state,
            "candidates": {"matched": 1, "absent-but-unresolved": 0, "ambiguous": 2}[state],
            "unversioned_candidates": 0,
        }
    ]
    assert not (root / "executed").exists()


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
        oracle.parse_json('{"Deps":[],"Deps":[1]}')


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity", "1e999", "-1e999"])
def test_nonstandard_json_constants_fail_closed(constant):
    with pytest.raises(ValueError):
        oracle.parse_json('{"extra":' + constant + "}")
