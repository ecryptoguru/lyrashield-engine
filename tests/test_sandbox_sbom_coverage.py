"""End-to-end bounded SBOM coverage qualification over exact image evidence."""

# ruff: noqa: E501

import hashlib
import io
import json
import runpy
import subprocess
import sys
import tarfile
from pathlib import Path
from urllib.parse import quote

import pytest


ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "scripts" / "check_sandbox_sbom_coverage.py"
API = runpy.run_path(str(SCRIPT))
IMAGE = "ghcr.io/example/sandbox"
COMMENT = "evident-by: indicates the package's existence is evident by the given file"
GOLDEN = bytes.fromhex("e40d87672c13de4365f2e3f66348a8ec70fee8c201d60586ff0286c9691ea47a")
URL_SAFE = "-_.!~*'()"
CONTAINER_ID = "f" * 64
APPLICATIONS = [
    ("httpx", "github.com/projectdiscovery/httpx", "v1.7.5", "/home/pentester/go/bin/httpx"),
    ("katana", "github.com/projectdiscovery/katana", "v1.6.2", "/home/pentester/go/bin/katana"),
    ("gospider", "github.com/jaeles-project/gospider", "v1.1.7", "/home/pentester/go/bin/gospider"),
    (
        "interactsh-client",
        "github.com/projectdiscovery/interactsh",
        "v1.3.1",
        "/home/pentester/go/bin/interactsh-client",
    ),
    ("vulnx", "github.com/projectdiscovery/vulnx/v2", "v2.0.3", "/home/pentester/go/bin/vulnx"),
    ("gitleaks", "github.com/zricethezav/gitleaks/v8", "v8.30.1", "/usr/local/bin/gitleaks"),
    ("trivy", "github.com/aquasecurity/trivy", "v0.73.0", "/usr/local/bin/trivy"),
    (
        "trufflehog",
        "github.com/trufflesecurity/trufflehog/v3",
        "v3.99.2",
        "/usr/local/bin/trufflehog",
    ),
    ("ffuf", "github.com/ffuf/ffuf/v2", "v2.2.1", "/usr/bin/ffuf"),
    ("naabu", "github.com/projectdiscovery/naabu/v2", "v2.6.1", "/usr/bin/naabu"),
    ("nuclei", "github.com/projectdiscovery/nuclei/v3", "v3.11.1", "/usr/bin/nuclei"),
    ("subfinder", "github.com/projectdiscovery/subfinder/v2", "v2.16.0", "/usr/bin/subfinder"),
]


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def add(tar, name, data=b"", entry_type=tarfile.REGTYPE):
    info = tarfile.TarInfo(name)
    info.type = entry_type
    info.size = len(data)
    tar.addfile(info, io.BytesIO(data) if data else None)


def binary_for(module):
    header = bytearray(32)
    header[:6] = b"\x7fELF\x02\x01"
    header[16:18] = (2).to_bytes(2, "little")
    header[18:20] = (62).to_bytes(2, "little")
    header[20:] = module.encode()
    return bytes(header)


def write_apps(tmp_path):
    normal = []
    distro = []
    for name, module, version, path in APPLICATIONS[:8]:
        normal.append(
            {
                "name": name,
                "module": module,
                "version": version,
                "commit": "a" * 40,
                "repository": "example/repository",
                "archive_sha256": "b" * 64,
                "binary": path,
            }
        )
    for _, module, version, path in APPLICATIONS[8:]:
        distro.append(
            {
                "type": "application",
                "name": module,
                "version": version,
                "purl": f"pkg:golang/{module}@{version}",
                "bom-ref": f"pkg:golang/{module}@{version}",
                "properties": [{"name": "lyrashield:binary:path", "value": path}],
            }
        )
    applications = {"schema_version": 1, "applications": normal}
    supplement = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "components": distro,
    }
    application_path = tmp_path / "applications.json"
    distro_path = tmp_path / "distro-applications.cdx.json"
    application_path.write_text(json.dumps(applications))
    distro_path.write_text(json.dumps(supplement))
    return application_path, distro_path


def write_spdx(tmp_path, child):
    packages = [
        {
            "name": IMAGE,
            "SPDXID": "SPDXRef-Image",
            "versionInfo": child,
            "checksums": [{"algorithm": "SHA256", "checksumValue": child[7:]}],
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": (
                        f"pkg:oci/{quote(IMAGE, safe=URL_SAFE)}@"
                        f"{quote(child, safe=URL_SAFE)}?arch=amd64"
                    ),
                }
            ],
        },
        {
            "name": "example",
            "SPDXID": "SPDXRef-Deb",
            "versionInfo": "1.0",
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": "pkg:deb/debian/example@1.0?arch=amd64",
                }
            ],
        },
        {
            "name": "example",
            "SPDXID": "SPDXRef-Pypi",
            "versionInfo": "1.0",
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": "pkg:pypi/example@1.0",
                }
            ],
        },
        {
            "name": "example",
            "SPDXID": "SPDXRef-Npm",
            "versionInfo": "1.0.0",
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": "pkg:npm/example@1.0.0",
                }
            ],
        },
        {
            "name": "example.com/dependency",
            "SPDXID": "SPDXRef-Dependency",
            "versionInfo": "v1.2.3",
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": "pkg:golang/example.com/dependency@v1.2.3",
                }
            ],
        },
        {
            "name": "stdlib",
            "SPDXID": "SPDXRef-Stdlib",
            "versionInfo": "go1.27.3",
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": "pkg:golang/stdlib@1.27.3",
                }
            ],
        },
    ]
    files = []
    relationships = [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": "SPDXRef-Image",
        }
    ]
    for index, (_, module, _, path) in enumerate(APPLICATIONS):
        package_id = f"SPDXRef-Main-{index}"
        file_id = f"SPDXRef-Binary-{index}"
        packages.append(
            {
                "name": module,
                "SPDXID": package_id,
                "versionInfo": "UNKNOWN",
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": f"pkg:golang/{module}",
                    }
                ],
            }
        )
        files.append(
            {
                "fileName": path[1:],
                "SPDXID": file_id,
                "checksums": [
                    {
                        "algorithm": "SHA256",
                        "checksumValue": hashlib.sha256(binary_for(module)).hexdigest(),
                    }
                ],
            }
        )
        relationships.extend(
            {
                "spdxElementId": source,
                "relatedSpdxElement": file_id,
                "relationshipType": "OTHER",
                "comment": COMMENT,
            }
            for source in (package_id, "SPDXRef-Dependency", "SPDXRef-Stdlib")
        )
    document = {
        "spdxVersion": "SPDX-2.3",
        "SPDXID": "SPDXRef-DOCUMENT",
        "creationInfo": {"creators": ["Tool: syft-1.56.0"]},
        "packages": packages,
        "files": files,
        "relationships": relationships,
    }
    path = tmp_path / "sandbox-amd64.spdx.json"
    raw = json.dumps(document).encode()
    path.write_bytes(raw)
    return path, raw


def write_rootfs(tmp_path):
    path = tmp_path / "rootfs.tar"
    with tarfile.open(path, mode="w") as tar:
        add(
            tar,
            "var/lib/dpkg/status",
            b"Package: example\nStatus: install ok installed\nVersion: 1.0\nArchitecture: amd64\n",
        )
        add(
            tar,
            "app/.venv/lib/python3.14/site-packages/example-1.0.dist-info/METADATA",
            b"Name: example\nVersion: 1.0\n",
        )
        add(
            tar,
            "home/pentester/.npm-tools/node_modules/example/package.json",
            b'{"name":"example","version":"1.0.0"}',
        )
        for _, module, _, binary_path in APPLICATIONS:
            add(tar, binary_path[1:], binary_for(module))
        add(tar, "usr/local/bin/safe-link-target", b"regular")
        info = tarfile.TarInfo("usr/local/bin/safe-link")
        info.type = tarfile.SYMTYPE
        info.linkname = "safe-link-target"
        tar.addfile(info)
    return path, path.read_bytes()


def write_go_tool(tmp_path):
    path = tmp_path / "go"
    path.write_text(
        """#!/bin/sh
set -eu
if [ "$1" = version ] && [ -z "${2:-}" ]; then
  printf 'go version go1.27.3 linux/amd64\\n'
  exit 0
fi
if [ "$1" = version ] && [ "${2:-}" = -m ]; then
  for last do :; done
  module="$(tail -c +21 "$last")"
  printf '{"GoVersion":"go1.27.3","Path":"%s","Main":{"Path":"%s","Version":"(devel)"},"Deps":[{"Path":"example.com/dependency","Version":"v1.2.3"}],"Settings":[{"Key":"GOOS","Value":"linux"},{"Key":"GOARCH","Value":"amd64"}]}\\n' "$module" "$module"
  exit 0
fi
exit 1
"""
    )
    path.chmod(0o755)
    return path, hashlib.sha256(path.read_bytes()).hexdigest()


def setup_platform(tmp_path):
    application_path = tmp_path / "applications.json"
    distro_path = tmp_path / "distro.json"
    application_path, distro_path = write_apps(tmp_path)
    config = json.dumps(
        {
            "os": "linux",
            "architecture": "amd64",
            "rootfs": {"type": "layers", "diff_ids": ["sha256:" + "e" * 64]},
        }
    ).encode()
    config_path = tmp_path / "config.json"
    config_path.write_bytes(config)
    manifest = json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": digest(config),
                "size": len(config),
            },
            "layers": [
                {
                    "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                    "digest": "sha256:" + "c" * 64,
                    "size": 123,
                }
            ],
        }
    ).encode()
    manifest_path = tmp_path / "amd64.manifest.json"
    manifest_path.write_bytes(manifest)
    child = digest(manifest)
    spdx_path, spdx_raw = write_spdx(tmp_path, child)
    qualification = {
        "schema": "lyrashield.sandbox.qualification.v1",
        "engineRevision": "a" * 40,
        "workflowRevision": "b" * 40,
        "runId": "123",
        "runAttempt": "1",
        "indexDigest": "sha256:" + "1" * 64,
        "platformManifests": {"amd64": child, "arm64": "sha256:" + "9" * 64},
    }
    predicate = {
        "schema": "lyrashield.sandbox.sbom.v1",
        "indexDigest": qualification["indexDigest"],
        "engineRevision": "a" * 40,
        "workflowRevision": "b" * 40,
        "runId": "123",
        "runAttempt": "1",
        "platforms": {
            "amd64": {
                "manifestDigest": child,
                "configDigest": digest(config),
                "documentDigest": digest(spdx_raw),
                "size": len(spdx_raw),
                "filename": spdx_path.name,
            },
            "arm64": {
                "manifestDigest": "sha256:" + "9" * 64,
                "configDigest": "sha256:" + "8" * 64,
                "documentDigest": "sha256:" + "7" * 64,
                "size": 1,
                "filename": "sandbox-arm64.spdx.json",
            },
        },
    }
    qualification_path = tmp_path / "qualification.json"
    predicate_path = tmp_path / "sbom-predicate.json"
    qualification_path.write_text(json.dumps(qualification))
    predicate_path.write_text(json.dumps(predicate))
    image_inspect = tmp_path / "image-inspect.json"
    image_inspect.write_text(
        json.dumps(
            [
                {
                    "Id": digest(config),
                    "Os": "linux",
                    "Architecture": "amd64",
                    "RootFS": {"Type": "layers", "Layers": ["sha256:" + "e" * 64]},
                }
            ]
        )
    )
    container_inspect = tmp_path / "container-inspect.json"
    container_inspect.write_text(
        json.dumps(
            [
                {
                    "Id": CONTAINER_ID,
                    "Image": digest(config),
                    "State": {"Status": "created", "Running": False, "Pid": 0},
                    "Mounts": [],
                    "HostConfig": {"Binds": None},
                }
            ]
        )
    )
    rootfs_path, rootfs_raw = write_rootfs(tmp_path)
    go_tool, go_tool_digest = write_go_tool(tmp_path)
    return {
        "application_path": application_path,
        "distro_path": distro_path,
        "config_path": config_path,
        "manifest_path": manifest_path,
        "spdx_path": spdx_path,
        "qualification_path": qualification_path,
        "predicate_path": predicate_path,
        "image_inspect": image_inspect,
        "container_inspect": container_inspect,
        "rootfs_path": rootfs_path,
        "rootfs_digest": digest(rootfs_raw),
        "go_tool": go_tool,
        "go_tool_digest": go_tool_digest,
        "child": child,
        "config_digest": digest(config),
    }


def platform_command(fixture):
    return [
        sys.executable,
        str(SCRIPT),
        "platform",
        "--architecture",
        "amd64",
        "--image",
        IMAGE,
        "--qualification",
        str(fixture["qualification_path"]),
        "--sbom-predicate",
        str(fixture["predicate_path"]),
        "--manifest",
        str(fixture["manifest_path"]),
        "--config",
        str(fixture["config_path"]),
        "--image-inspect",
        str(fixture["image_inspect"]),
        "--container-inspect",
        str(fixture["container_inspect"]),
        "--container-id",
        CONTAINER_ID,
        "--rootfs",
        str(fixture["rootfs_path"]),
        "--expected-rootfs-digest",
        fixture["rootfs_digest"],
        "--spdx",
        str(fixture["spdx_path"]),
        "--go-tool",
        str(fixture["go_tool"]),
        "--expected-go-tool-digest",
        fixture["go_tool_digest"],
        "--applications",
        str(fixture["application_path"]),
        "--distro-applications",
        str(fixture["distro_path"]),
        "--docker-server",
        "29.0.0/0367cbe",
        "--capture-dir",
        str(fixture["rootfs_path"].parent / "captures"),
        "--output",
        str(fixture["rootfs_path"].parent / "receipt.json"),
    ]


def run_platform_command(fixture, command=None):
    command = command or platform_command(fixture)
    capture_dir = Path(command[command.index("--capture-dir") + 1])
    capture_dir.mkdir()
    capture_dir.chmod(0o700)
    return subprocess.run(  # noqa: S603 - fixed repository gate and test-owned inputs
        command, capture_output=True, text=True, check=False
    )


def test_platform_gate_binds_config_rootfs_spdx_and_all_twelve_go_files(tmp_path):
    assert SCRIPT.is_file(), "bounded coverage gate is missing"
    fixture = setup_platform(tmp_path)
    result = run_platform_command(fixture)
    assert result.returncode == 0, result.stderr
    receipt = json.loads((tmp_path / "receipt.json").read_text())
    assert receipt["schema"] == "lyrashield.sandbox.sbom-coverage.platform.v1"
    assert receipt["status"] == "bounded_scope_matched"
    assert receipt["manifestDigest"] == fixture["child"]
    assert receipt["configDigest"] == fixture["config_digest"]
    assert receipt["containerId"] == CONTAINER_ID
    assert receipt["rootfs"]["sha256"] == fixture["rootfs_digest"]
    assert receipt["spdx"]["documentDigest"] == digest(fixture["spdx_path"].read_bytes())
    assert receipt["inventoryCounts"] == {"deb": 1, "pypi": 1, "npm": 1, "goApplications": 12}
    assert {app["name"] for app in receipt["goApplications"]} == {app[0] for app in APPLICATIONS}
    assert receipt["ignoredLinks"]["count"] == 1
    assert receipt["ignoredLinks"]["policy"] == {
        "id": "sandbox-bounded-package-link-policy",
        "version": 2,
    }
    assert receipt["limits"]["goBinaries"] == 12
    assert receipt["limits"]["rootfsExportBytes"] == 8 * 1024 * 1024 * 1024
    assert receipt["limits"]["rootfsExportSeconds"] == 900
    assert "not proof of image-wide package completeness" in receipt["limitations"][0]


def test_platform_gate_rejects_wrong_rootfs_digest_without_receipt(tmp_path):
    fixture = setup_platform(tmp_path)
    command = platform_command(fixture)
    command[command.index("--expected-rootfs-digest") + 1] = "sha256:" + "0" * 64
    capture_dir = Path(command[command.index("--capture-dir") + 1])
    capture_dir.mkdir()
    capture_dir.chmod(0o700)
    result = subprocess.run(  # noqa: S603 - fixed repository gate and test-owned inputs
        command, capture_output=True, text=True, check=False
    )
    assert result.returncode != 0
    assert not (tmp_path / "receipt.json").exists()


@pytest.mark.parametrize(
    "mutation",
    [
        "schema",
        "manifest_media_type",
        "config_media_type",
        "config_urls",
        "config_data",
        "missing_config",
    ],
)
def test_platform_gate_uses_one_strict_manifest_and_config_validator(tmp_path, mutation):
    fixture = setup_platform(tmp_path)
    manifest = json.loads(fixture["manifest_path"].read_text())
    if mutation == "schema":
        manifest["schemaVersion"] = 1
    elif mutation == "manifest_media_type":
        manifest["mediaType"] = "application/vnd.oci.image.index.v1+json"
    elif mutation == "config_media_type":
        manifest["config"]["mediaType"] = "application/json"
    elif mutation == "config_urls":
        manifest["config"]["urls"] = ["https://foreign.invalid/config"]
    elif mutation == "config_data":
        manifest["config"]["data"] = "e30="
    else:
        manifest.pop("config")
    raw = json.dumps(manifest, separators=(",", ":")).encode()
    fixture["manifest_path"].write_bytes(raw)
    child = digest(raw)
    qualification = json.loads(fixture["qualification_path"].read_text())
    qualification["platformManifests"]["amd64"] = child
    fixture["qualification_path"].write_text(json.dumps(qualification))
    predicate = json.loads(fixture["predicate_path"].read_text())
    predicate["platforms"]["amd64"]["manifestDigest"] = child
    fixture["predicate_path"].write_text(json.dumps(predicate))
    result = run_platform_gate(fixture)
    assert result.returncode != 0
    assert not (tmp_path / "receipt.json").exists()


def test_platform_gate_enforces_the_effective_rootfs_export_cap(tmp_path, monkeypatch):
    fixture = setup_platform(tmp_path)
    scan = API["scan_bound_rootfs"]
    monkeypatch.setitem(
        scan.__globals__, "MAX_ROOTFS_EXPORT_BYTES", fixture["rootfs_path"].stat().st_size - 1
    )
    with pytest.raises(ValueError, match="rootfs export"):
        scan(fixture["rootfs_path"], fixture["rootfs_digest"], (), None)


def test_platform_gate_cleans_captured_binaries_after_late_rootfs_failure(tmp_path):
    fixture = setup_platform(tmp_path)
    raw = bytearray(fixture["rootfs_path"].read_bytes())
    raw[-1] = 1
    fixture["rootfs_path"].write_bytes(raw)
    command = platform_command(fixture)
    command[command.index("--expected-rootfs-digest") + 1] = digest(raw)
    result = run_platform_command(fixture, command)
    assert result.returncode != 0
    capture_dir = Path(command[command.index("--capture-dir") + 1])
    assert list(capture_dir.iterdir()) == []
    assert not (tmp_path / "receipt.json").exists()


def test_platform_gate_binds_the_expected_container_id(tmp_path):
    fixture = setup_platform(tmp_path)
    command = platform_command(fixture)
    command[command.index("--container-id") + 1] = "e" * 64
    result = run_platform_command(fixture, command)
    assert result.returncode != 0
    assert not (tmp_path / "receipt.json").exists()


@pytest.mark.parametrize("mutation", ["running", "mounted", "wrong_image"])
def test_platform_gate_rejects_containers_not_created_from_the_exact_unstarted_image(
    tmp_path, mutation
):
    fixture = setup_platform(tmp_path)
    records = json.loads(fixture["container_inspect"].read_text())
    if mutation == "running":
        records[0]["State"] = {"Status": "running", "Running": True, "Pid": 123}
    elif mutation == "mounted":
        records[0]["Mounts"] = [{"Destination": "/workspace"}]
    else:
        records[0]["Image"] = "sha256:" + "0" * 64
    fixture["container_inspect"].write_text(json.dumps(records))
    result = run_platform_gate(fixture)
    assert result.returncode != 0
    assert not (tmp_path / "receipt.json").exists()


def test_platform_receipt_is_byte_deterministic_across_independent_capture_directories(tmp_path):
    fixture = setup_platform(tmp_path)
    assert run_platform_gate(fixture).returncode == 0
    first = (tmp_path / "receipt.json").read_bytes()
    second_capture = tmp_path / "captures-second"
    second_capture.mkdir()
    second_capture.chmod(0o700)
    command = platform_command(fixture)
    command[command.index("--capture-dir") + 1] = str(second_capture)
    command[command.index("--output") + 1] = str(tmp_path / "receipt-second.json")
    result = subprocess.run(  # noqa: S603 - fixed repository gate and test-owned inputs
        command, capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stderr
    assert (tmp_path / "receipt-second.json").read_bytes() == first


def run_platform_gate(fixture):
    return run_platform_command(fixture)


def prepare_receipts(tmp_path):
    fixture = setup_platform(tmp_path)
    result = run_platform_gate(fixture)
    assert result.returncode == 0, result.stderr
    amd64 = tmp_path / "receipt.json"
    qualification = json.loads(fixture["qualification_path"].read_text())
    predicate = json.loads(fixture["predicate_path"].read_text())
    arm = json.loads(amd64.read_text())
    arm["architecture"] = "arm64"
    arm["manifestDigest"] = qualification["platformManifests"]["arm64"]
    arm["configDigest"] = predicate["platforms"]["arm64"]["configDigest"]
    arm["spdx"] = predicate["platforms"]["arm64"]
    arm["rootfs"] = {"sha256": "sha256:" + "d" * 64, "size": 123}
    arm64 = tmp_path / "receipt-arm64.json"
    arm64.write_text(json.dumps(arm, sort_keys=True, separators=(",", ":")) + "\n")
    return fixture, amd64, arm64


def aggregate_command(fixture, amd64, arm64):
    return [
        sys.executable,
        str(SCRIPT),
        "aggregate",
        "--qualification",
        str(fixture["qualification_path"]),
        "--sbom-predicate",
        str(fixture["predicate_path"]),
        "--image",
        IMAGE,
        "--applications",
        str(fixture["application_path"]),
        "--distro-applications",
        str(fixture["distro_path"]),
        "--expected-go-tool-digest",
        fixture["go_tool_digest"],
        "--docker-server",
        "29.0.0/0367cbe",
        "--amd64-receipt",
        str(amd64),
        "--arm64-receipt",
        str(arm64),
        "--output",
        str(fixture["rootfs_path"].parent / "coverage-predicate.json"),
    ]


def test_aggregate_requires_both_exact_receipts_and_emits_signed_claim_contract(tmp_path):
    fixture, amd64, arm64 = prepare_receipts(tmp_path)
    command = aggregate_command(fixture, amd64, arm64)
    result = subprocess.run(  # noqa: S603 - fixed repository gate and test-owned inputs
        command, capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stderr
    predicate = json.loads((tmp_path / "coverage-predicate.json").read_text())
    assert predicate["schema"] == "lyrashield.sandbox.sbom-coverage.v1"
    assert predicate["policy"] == {"id": "sandbox-bounded-package-coverage", "version": 1}
    assert set(predicate["platforms"]) == {"amd64", "arm64"}
    assert predicate["platforms"]["amd64"]["receiptDigest"] == digest(amd64.read_bytes())
    assert predicate["platforms"]["arm64"]["receiptDigest"] == digest(arm64.read_bytes())
    assert len(predicate["requiredGoApplications"]) == 12
    assert predicate["platforms"]["amd64"]["containerId"] == CONTAINER_ID
    assert predicate["platforms"]["amd64"]["ignoredLinks"]["policy"]["version"] == 2
    assert predicate["platforms"]["amd64"]["limits"]["rootfsExportBytes"] == 8 * 1024 * 1024 * 1024
    assert "not proof of image-wide package completeness" in predicate["limitations"][0]


def test_aggregate_rejects_receipt_that_differs_from_signed_platform_binding(tmp_path):
    fixture, amd64, arm64 = prepare_receipts(tmp_path)
    altered = json.loads(arm64.read_text())
    altered["configDigest"] = "sha256:" + "0" * 64
    arm64.write_text(json.dumps(altered, sort_keys=True, separators=(",", ":")) + "\n")
    result = subprocess.run(  # noqa: S603 - fixed repository gate and test-owned inputs
        aggregate_command(fixture, amd64, arm64), capture_output=True, text=True, check=False
    )
    assert result.returncode != 0
    assert not (tmp_path / "coverage-predicate.json").exists()


@pytest.mark.parametrize(
    "field,value",
    [
        ("limits.rootfsExportBytes", 1),
        ("limits.rootfsExportSeconds", 1),
        ("ignoredLinks.policy.version", 999),
        ("goToolSha256", "0" * 64),
        ("exporter.dockerServer", "untrusted"),
        ("goApplications.0.binarySha256", "not-a-digest"),
        ("goApplications.0.pinnedVersion", "v0.0.0"),
        ("goApplications.0.binaryPath", "/usr/local/bin/not-the-app"),
    ],
)
def test_aggregate_rejects_incomplete_or_altered_platform_receipts(tmp_path, field, value):
    fixture, amd64, arm64 = prepare_receipts(tmp_path)
    receipt = json.loads(arm64.read_text())
    target = receipt
    parts = field.split(".")
    for part in parts[:-1]:
        target = target[int(part)] if isinstance(target, list) else target[part]
    leaf = parts[-1]
    if isinstance(target, list):
        target[int(leaf)] = value
    else:
        target[leaf] = value
    arm64.write_text(json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n")
    result = subprocess.run(  # noqa: S603 - fixed repository gate and test-owned inputs
        aggregate_command(fixture, amd64, arm64), capture_output=True, text=True, check=False
    )
    assert result.returncode != 0
    assert not (tmp_path / "coverage-predicate.json").exists()
