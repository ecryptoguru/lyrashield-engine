"""Independent byte binding, final metadata selection and trust-boundary regressions."""

import gzip
import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
from types import SimpleNamespace

import pytest

from scripts import verify_sandbox_package_inventory as verifier
from scripts.check_sbom_inventory import collect_metadata
from scripts.verify_oci_layer_binding import OCI_CONFIG, OCI_GZIP, OCI_MANIFEST


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def layer(entries):
    stream = io.BytesIO()
    directories = set()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, kind, value in entries:
            parts = name.split("/")
            for count in range(1, len(parts)):
                parent = "/".join(parts[:count])
                if parent not in directories:
                    item = tarfile.TarInfo(parent)
                    item.type = tarfile.DIRTYPE
                    archive.addfile(item)
                    directories.add(parent)
            item = tarfile.TarInfo(name)
            if kind == "file":
                item.size = len(value)
                archive.addfile(item, io.BytesIO(value))
            else:
                item.type = tarfile.SYMTYPE if kind == "symlink" else tarfile.LNKTYPE
                item.linkname = value
                archive.addfile(item)
    return stream.getvalue()


def image(tmp_path, raw_layers, *, architecture="amd64", diff_ids=None):
    blobs = tmp_path / "blobs"
    blobs.mkdir(mode=0o700)

    def store(raw):
        identity = digest(raw)
        (blobs / identity[7:]).write_bytes(raw)
        return identity

    layers = []
    for raw in raw_layers:
        compressed = gzip.compress(raw, mtime=0)
        layers.append({"digest": store(compressed), "size": len(compressed), "mediaType": OCI_GZIP})
    config = {
        "os": "linux",
        "architecture": architecture,
        "rootfs": {"type": "layers", "diff_ids": diff_ids or [digest(x) for x in raw_layers]},
    }
    raw = json.dumps(config).encode()
    manifest = {
        "schemaVersion": 2,
        "mediaType": OCI_MANIFEST,
        "config": {"digest": store(raw), "size": len(raw), "mediaType": OCI_CONFIG},
        "layers": layers,
    }
    identity = store(json.dumps(manifest).encode())
    return blobs, identity, manifest, config


def metadata_entries():
    return [
        (
            "var/lib/dpkg/status",
            "file",
            b"Package: safe\nVersion: 1\nArchitecture: amd64\nStatus: install ok installed\n\n",
        ),
        (
            "usr/lib/python3/dist-packages/safe.dist-info/METADATA",
            "file",
            b"Name: safe\nVersion: 1\n",
        ),
        ("usr/local/lib/node_modules/safe/package.json", "file", b'{"name":"safe","version":"1"}'),
        ("usr/bin/probe", "file", b"inert ELF payload, never executed"),
    ]


def observe(tmp_path, layers):
    blobs, identity, manifest, config = image(tmp_path, layers)
    fd = os.open(blobs, os.O_RDONLY | os.O_DIRECTORY)
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    captures = private / "captures"
    captures.mkdir(mode=0o700)
    applications = [{"binary": "/usr/bin/probe"}]
    try:
        model = verifier.model_verified_image(fd, identity, "linux/amd64")
        selected = verifier.selected_payloads(model, applications)
        payloads = verifier.capture_payloads(fd, manifest, config, selected, private)
        with io.BytesIO() as stream:
            verifier.scoped_archive(model, payloads, stream, applications)
            stream.seek(0)
            result = verifier.scan_rootfs(stream, ["/usr/bin/probe"], captures)
        return result, payloads, model
    finally:
        os.close(fd)


def test_final_inventory_uses_ordered_changes_and_original_verified_extents(tmp_path):
    first = layer(metadata_entries())
    second = layer(
        [
            ("usr/local/lib/node_modules/safe/.wh.package.json", "file", b""),
            (
                "usr/local/lib/node_modules/safe/package.json",
                "file",
                b'{"name":"safe","version":"2"}',
            ),
        ]
    )
    result, payloads, model = observe(tmp_path, [first, second])
    assert result["unresolved"] == []
    assert result["inventory"] == {
        "deb": {("safe", "1", "amd64")},
        "pypi": {("safe", "1")},
        "npm": {("safe", "2")},
    }
    assert payloads["usr/bin/probe"].read_bytes() == b"inert ELF payload, never executed"
    assert model.entries["usr/local/lib/node_modules/safe/package.json"].inode.source_layer == 1
    assert not model.runtime_equivalent and not model.release_qualified
    assert not (tmp_path / "usr").exists()


@pytest.mark.parametrize("mutation", ["compressed", "diffid", "platform", "missing"])
def test_corrupt_or_wrong_native_bytes_never_produce_a_model(tmp_path, mutation):
    blobs, identity, manifest, config = image(tmp_path, [layer(metadata_entries())])
    if mutation == "compressed":
        path = blobs / manifest["layers"][0]["digest"][7:]
        raw = bytearray(path.read_bytes())
        raw[-9] ^= 1
        path.write_bytes(raw)
    elif mutation == "diffid":
        config["rootfs"]["diff_ids"] = ["sha256:" + "0" * 64]
        raw = json.dumps(config).encode()
        cfg = manifest["config"]
        cfg["digest"] = digest(raw)
        cfg["size"] = len(raw)
        (blobs / digest(raw)[7:]).write_bytes(raw)
        raw = json.dumps(manifest).encode()
        identity = digest(raw)
        (blobs / identity[7:]).write_bytes(raw)
    elif mutation == "missing":
        (blobs / manifest["layers"][0]["digest"][7:]).unlink()
    fd = os.open(blobs, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(ValueError, match="metadata overlay incomplete"):
            verifier.model_verified_image(
                fd, identity, "linux/arm64" if mutation == "platform" else "linux/amd64"
            )
    finally:
        os.close(fd)


def test_second_byte_pass_rejects_payload_mutation_before_inventory(tmp_path):
    blobs, identity, manifest, config = image(tmp_path, [layer(metadata_entries())])
    fd = os.open(blobs, os.O_RDONLY | os.O_DIRECTORY)
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    try:
        model = verifier.model_verified_image(fd, identity, "linux/amd64")
        selected = verifier.selected_payloads(model, [{"binary": "/usr/bin/probe"}])
        path = blobs / manifest["layers"][0]["digest"][7:]
        raw = path.read_bytes()
        path.write_bytes(raw[:-1])
        with pytest.raises(ValueError):
            verifier.capture_payloads(fd, manifest, config, selected, private)
    finally:
        os.close(fd)


def test_metadata_boundary_alias_is_incomplete(tmp_path):
    entries = [entry for entry in metadata_entries() if entry[0] != "var/lib/dpkg/status"]
    entries.append(("var/lib/dpkg/status", "symlink", "/unscanned/status"))
    result, _, _ = observe(tmp_path, [layer(entries)])
    assert result["unresolved"]
    assert result["inventory"]["deb"] == set()


def test_unselected_guarded_hardlink_keeps_its_header_and_fails_inventory(tmp_path):
    entries = metadata_entries()
    entries.extend(
        [
            ("usr/bin/other", "file", b"unselected bytes"),
            ("usr/local/lib/node_modules/safe/linked-file", "hardlink", "usr/bin/other"),
        ]
    )
    result, _, model = observe(tmp_path, [layer(entries)])
    assert (
        model.entries["usr/local/lib/node_modules/safe/linked-file"].hardlink_target
        == "usr/bin/other"
    )
    assert any(
        item["reason"] == "link at a guarded inventory boundary" for item in result["unresolved"]
    )


@pytest.mark.parametrize("version", ["1", "2"])
def test_duplicate_installed_debian_key_fails_even_when_sets_would_collapse(version):
    first = b"Package: safe\nVersion: 1\nArchitecture: amd64\nStatus: install ok installed\n\n"
    second = first.replace(b"Version: 1", ("Version: " + version).encode())
    with pytest.raises(ValueError, match="duplicate installed Debian"):
        collect_metadata("deb", first + second)


def test_valid_debian_multiarch_remains_distinct():
    first = b"Package: safe\nVersion: 1\nArchitecture: amd64\nStatus: install ok installed\n\n"
    second = first.replace(b"Architecture: amd64", b"Architecture: arm64")
    assert collect_metadata("deb", first + second) == {
        ("safe", "1", "amd64"),
        ("safe", "1", "arm64"),
    }


def test_guarded_hardlink_and_oversized_payload_fail_closed(tmp_path, monkeypatch):
    entries = metadata_entries()
    entries.append(("usr/bin/alias", "hardlink", "usr/bin/probe"))
    with pytest.raises(ValueError, match="hardlink"):
        observe(tmp_path, [layer(entries)])
    second = tmp_path / "second"
    second.mkdir()
    monkeypatch.setattr(verifier, "MAX_METADATA_BYTES", 4)
    with pytest.raises(ValueError, match="exceeds bound"):
        observe(second, [layer(metadata_entries())])


def test_scoped_archive_rejects_a_single_write_past_its_cap(tmp_path, monkeypatch):
    monkeypatch.setattr(verifier, "MAX_SCOPED_TAR_BYTES", 1024)
    with pytest.raises(ValueError, match="scoped archive exceeds bound"):
        observe(tmp_path, [layer(metadata_entries())])


@pytest.mark.parametrize("ecosystem", ["deb", "pypi", "npm"])
def test_each_observed_ecosystem_requires_the_correct_typed_spdx_identity(tmp_path, ecosystem):
    result, _, _ = observe(tmp_path, [layer(metadata_entries())])
    purls = {
        "deb": "pkg:deb/debian/safe@1?arch=amd64",
        "pypi": "pkg:pypi/safe@1",
        "npm": "pkg:npm/safe@1",
    }
    packages = [
        {
            "name": "safe",
            "versionInfo": "1",
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": purl,
                }
            ],
        }
        for purl in purls.values()
    ]
    verifier.validate_inventory(result["inventory"], {"packages": packages})
    packages[list(purls).index(ecosystem)]["externalRefs"][0]["referenceLocator"] = purls[
        ecosystem
    ].replace("@1", "@2")
    with pytest.raises(ValueError, match="missing bounded filesystem identities"):
        verifier.validate_inventory(result["inventory"], {"packages": packages})


def policy_record():
    args = SimpleNamespace(
        repo=verifier.REPOSITORY,
        image=verifier.IMAGE,
        ref="refs/heads/main",
        revision="a" * 40,
        digest="sha256:" + "b" * 64,
        run_id="123",
        run_attempt="1",
    )
    invocation = f"https://github.com/{args.repo}/actions/runs/123/attempts/1"
    certificate = {
        "issuer": "https://token.actions.githubusercontent.com",
        "buildSignerURI": f"https://github.com/{args.repo}/.github/workflows/publish-sandbox.yml@{args.ref}",
        "buildSignerDigest": args.revision,
        "sourceRepositoryDigest": args.revision,
        "sourceRepositoryURI": f"https://github.com/{args.repo}",
        "sourceRepositoryRef": args.ref,
        "runnerEnvironment": "github-hosted",
        "runInvocationURI": invocation,
    }
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "predicateType": verifier.SBOM_TYPE,
        "subject": [{"name": args.image, "digest": {"sha256": args.digest[7:]}}],
        "predicate": {"test": "bounded"},
    }
    return args, {
        "verificationResult": {"signature": {"certificate": certificate}, "statement": statement}
    }


@pytest.mark.parametrize(
    "field",
    ["buildSignerDigest", "sourceRepositoryDigest", "runInvocationURI", "runnerEnvironment"],
)
def test_signed_policy_rejects_wrong_source_run_or_runner(field):
    args, record = policy_record()
    record["verificationResult"]["signature"]["certificate"][field] = "untrusted"
    with pytest.raises(ValueError, match="authenticated predicate"):
        verifier.verified_predicate([record], verifier.SBOM_TYPE, args)


def test_signed_policy_rejects_ambiguous_claims_and_authentication_failure(tmp_path, monkeypatch):
    args, record = policy_record()
    assert verifier.verified_predicate([record], verifier.SBOM_TYPE, args) == {"test": "bounded"}
    with pytest.raises(ValueError, match="ambiguous"):
        verifier.verified_predicate([record, record], verifier.SBOM_TYPE, args)

    def failing_command(*_args):
        raise ValueError("signature verification failed")

    monkeypatch.setattr(verifier, "bounded_command", failing_command)
    monkeypatch.setattr(verifier, "trusted_tool", lambda path, _expected: path)
    raw = b'{"schemaVersion":2}'
    index = tmp_path / "index.json"
    index.write_bytes(raw)
    args.digest = digest(raw)
    with pytest.raises(ValueError, match="signature"):
        verifier.authenticate(index, args)


def test_authentication_fetches_exact_oci_bundles_and_hashes_local_index(tmp_path, monkeypatch):
    args, _record = policy_record()
    raw = b'{"schemaVersion":2}'
    index = tmp_path / "index.json"
    index.write_bytes(raw)
    args.digest = digest(raw)
    commands = []

    def run(command, _limit, _timeout):
        commands.append(command)
        return b"[]"

    monkeypatch.setattr(verifier, "trusted_tool", lambda path, _expected: path)
    monkeypatch.setattr(verifier, "bounded_command", run)
    monkeypatch.setattr(verifier, "verified_predicate", lambda *_args: {})
    assert len(verifier.authenticate(index, args)) == 4
    assert all(
        command[0] == "/usr/bin/gh"
        and command[3] == "oci://" + args.image + "@" + args.digest
        and "--bundle-from-oci" in command
        for command in commands
    )
    index.write_bytes(b"different bytes")
    commands.clear()
    with pytest.raises(ValueError, match="local index differs"):
        verifier.authenticate(index, args)
    assert not commands


def test_caller_supplied_executable_is_not_a_trust_anchor(tmp_path):
    candidate = tmp_path / "fake-go"
    candidate.write_bytes(b"fake trusted inspector")
    with pytest.raises(ValueError, match="protected"):
        verifier.trusted_tool(candidate, hashlib.sha256(candidate.read_bytes()).hexdigest())


def test_host_command_output_and_deadline_are_bounded(tmp_path):
    with pytest.raises(ValueError, match="command failed"):
        verifier.bounded_command([sys.executable, "-c", "print('x'*65536)"], 512, 5)
    marker = tmp_path / "pid"
    script = (
        "import os,pathlib,sys,time; "
        "pathlib.Path(sys.argv[1]).write_text(str(os.getpid())); time.sleep(10)"
    )
    with pytest.raises(subprocess.TimeoutExpired):
        verifier.bounded_command([sys.executable, "-c", script, str(marker)], 512, 0.25)
    pid = int(marker.read_text())
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)
