"""Per-file Go evidence must match one pinned binary and SPDX relationship slice."""

# ruff: noqa: PLR0912

import copy
import hashlib
import runpy
from pathlib import Path

import pytest


SCRIPT = Path(__file__).parents[1] / "scripts" / "sandbox_sbom_go.py"
COMMENT = "evident-by: indicates the package's existence is evident by the given file"
MODULE = "example.com/tool"
DEPENDENCY = "example.com/dependency"


@pytest.fixture(scope="module")
def api():
    assert SCRIPT.is_file(), "bound Go relationship verifier is missing"
    return runpy.run_path(str(SCRIPT))


def fixtures():
    raw = b"binary"
    document = {
        "spdxVersion": "SPDX-2.3",
        "SPDXID": "SPDXRef-DOCUMENT",
        "packages": [
            {
                "SPDXID": "SPDXRef-Main",
                "name": MODULE,
                "versionInfo": "UNKNOWN",
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": f"pkg:golang/{MODULE}",
                    }
                ],
            },
            {
                "SPDXID": "SPDXRef-Dependency",
                "name": DEPENDENCY,
                "versionInfo": "v1.2.3",
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": f"pkg:golang/{DEPENDENCY}@v1.2.3",
                    }
                ],
            },
            {
                "SPDXID": "SPDXRef-Stdlib",
                "name": "stdlib",
                "versionInfo": "go1.27.3",
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": "pkg:golang/stdlib@1.27.3",
                    }
                ],
            },
        ],
        "files": [
            {
                "SPDXID": "SPDXRef-Binary",
                "fileName": "usr/local/bin/tool",
                "checksums": [
                    {
                        "algorithm": "SHA256",
                        "checksumValue": hashlib.sha256(raw).hexdigest(),
                    }
                ],
            }
        ],
        "relationships": [
            {
                "spdxElementId": "SPDXRef-Main",
                "relatedSpdxElement": "SPDXRef-Binary",
                "relationshipType": "OTHER",
                "comment": COMMENT,
            },
            {
                "spdxElementId": "SPDXRef-Dependency",
                "relatedSpdxElement": "SPDXRef-Binary",
                "relationshipType": "OTHER",
                "comment": COMMENT,
            },
            {
                "spdxElementId": "SPDXRef-Stdlib",
                "relatedSpdxElement": "SPDXRef-Binary",
                "relationshipType": "OTHER",
                "comment": COMMENT,
            },
        ],
    }
    build_info = {
        "GoVersion": "go1.27.3",
        "Path": MODULE,
        "Main": {"Path": MODULE, "Version": "(devel)"},
        "Deps": [{"Path": DEPENDENCY, "Version": "v1.2.3"}],
        "Settings": [
            {"Key": "GOOS", "Value": "linux"},
            {"Key": "GOARCH", "Value": "amd64"},
        ],
    }
    return document, build_info, hashlib.sha256(raw).hexdigest()


def verify(api, document, build_info, binary_sha256=None):
    return api["verify_application"](
        document,
        build_info,
        architecture="amd64",
        expected_module=MODULE,
        binary_path="/usr/local/bin/tool",
        binary_sha256=binary_sha256 or fixtures()[2],
    )


def test_binds_main_dependency_and_checksum_to_one_attributed_file(api):
    document, build_info, _ = fixtures()
    result = verify(api, document, build_info)
    assert result == {
        "dependency_count": 1,
        "linked_package_count": 3,
        "main_spdx_package_id": "SPDXRef-Main",
        "spdx_file_id": "SPDXRef-Binary",
    }


def test_unrelated_spdx_file_with_a_non_normalized_name_does_not_hide_the_selected_slice(api):
    document, build_info, _ = fixtures()
    document["files"].append(
        {
            "SPDXID": "SPDXRef-Unrelated",
            "fileName": "/outside/the/pinned/scope",
            "checksums": [{"algorithm": "SHA256", "checksumValue": "0" * 64}],
        }
    )
    result = verify(api, document, build_info)
    assert result["spdx_file_id"] == "SPDXRef-Binary"


def test_direct_command_line_build_uses_one_exact_devel_self_module_as_main_proof(api):
    document, build_info, _ = fixtures()
    build_info["Path"] = "command-line-arguments"
    build_info["Main"] = {}
    build_info["Deps"].insert(0, {"Path": MODULE, "Version": "(devel)"})
    result = verify(api, document, build_info)
    assert result["dependency_count"] == 1
    assert result["main_spdx_package_id"] == "SPDXRef-Main"


def test_direct_command_line_build_rejects_a_different_self_module(api):
    document, build_info, _ = fixtures()
    build_info["Path"] = "command-line-arguments"
    build_info["Main"] = {}
    build_info["Deps"].insert(0, {"Path": "example.com/other", "Version": "(devel)"})
    with pytest.raises(ValueError):
        verify(api, document, build_info)


def test_rejects_noncanonical_spdx_element_ids(api):
    with pytest.raises(ValueError):
        api["_unique_id"]("SPDXRef-Bad ID", "package ID")
    with pytest.raises(ValueError):
        api["_unique_id"]("not-an-spdx-id", "file ID")


def test_package_inventory_is_bounded_before_relationship_indexing(api, monkeypatch):
    document, _, _ = fixtures()
    document["packages"].extend(
        [{"SPDXID": f"SPDXRef-Extra-{index}", "name": "example.com/extra"} for index in range(3)]
    )
    index = api["GoEvidenceIndex"]
    monkeypatch.setitem(index.__init__.__globals__, "MAX_PACKAGES", 2)
    with pytest.raises(ValueError, match="SPDX package"):
        index(document)


@pytest.mark.parametrize(
    "mutation",
    [
        "wrong_binary",
        "wrong_main",
        "wrong_arch",
        "wrong_file_checksum",
        "duplicate_file",
        "missing_relationship",
        "wrong_relationship_direction",
        "wrong_relationship_comment",
        "missing_dependency",
        "duplicate_dependency_identity",
        "extra_versioned_package",
        "non_go_package",
        "malformed_reference",
        "wrong_stdlib_version",
        "wrong_purl",
    ],
)
def test_rejects_any_incomplete_or_ambiguous_file_relationship_slice(api, mutation):
    document, build_info, binary_sha256 = fixtures()
    if mutation == "wrong_binary":
        binary_sha256 = "0" * 64
    elif mutation == "wrong_main":
        build_info["Main"]["Path"] = "example.com/other"
    elif mutation == "wrong_arch":
        build_info["Settings"][1]["Value"] = "arm64"
    elif mutation == "wrong_file_checksum":
        document["files"][0]["checksums"][0]["checksumValue"] = "0" * 64
    elif mutation == "duplicate_file":
        document["files"].append(
            copy.deepcopy(document["files"][0]) | {"SPDXID": "SPDXRef-Binary2"}
        )
    elif mutation == "missing_relationship":
        document["relationships"].pop()
    elif mutation == "wrong_relationship_direction":
        relationship = document["relationships"][0]
        relationship["spdxElementId"], relationship["relatedSpdxElement"] = (
            relationship["relatedSpdxElement"],
            relationship["spdxElementId"],
        )
    elif mutation == "wrong_relationship_comment":
        document["relationships"][1]["comment"] = "evident-by"
    elif mutation == "missing_dependency":
        document["relationships"].pop(1)
    elif mutation == "duplicate_dependency_identity":
        duplicate = copy.deepcopy(document["packages"][1])
        duplicate["SPDXID"] = "SPDXRef-Dependency-Copy"
        document["packages"].append(duplicate)
        document["relationships"].append(
            {
                "spdxElementId": duplicate["SPDXID"],
                "relatedSpdxElement": "SPDXRef-Binary",
                "relationshipType": "OTHER",
                "comment": COMMENT,
            }
        )
    elif mutation == "extra_versioned_package":
        document["packages"].append(
            {
                "SPDXID": "SPDXRef-Extra",
                "name": "example.com/extra",
                "versionInfo": "v9.9.9",
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": "pkg:golang/example.com/extra@v9.9.9",
                    }
                ],
            }
        )
        document["relationships"].append(
            {
                "spdxElementId": "SPDXRef-Extra",
                "relatedSpdxElement": "SPDXRef-Binary",
                "relationshipType": "OTHER",
                "comment": COMMENT,
            }
        )
    elif mutation == "non_go_package":
        package = copy.deepcopy(document["packages"][1])
        package["externalRefs"][0]["referenceLocator"] = "pkg:npm/dependency@1.2.3"
        document["packages"][1] = package
    elif mutation == "malformed_reference":
        document["packages"][0]["externalRefs"].append("not-an-external-reference")
    elif mutation == "wrong_stdlib_version":
        document["packages"][2]["externalRefs"][0]["referenceLocator"] = "pkg:golang/stdlib@1.26.5"
    elif mutation == "wrong_purl":
        document["packages"][1]["externalRefs"][0]["referenceLocator"] = (
            "pkg:golang/example.com/dependency@v9.9.9"
        )
    with pytest.raises(ValueError):
        verify(api, document, build_info, binary_sha256)
