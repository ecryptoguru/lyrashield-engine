"""Independently compare signed package inventories with local OCI layer bytes.

The CLI obtains signature verification itself; saved producer verification JSON
is never a trust input. Image paths remain inert. A conservative ordered header
model selects package metadata and Go payload extents, and a second complete
compressed-hash/DiffID pass copies only those extents into generated private
files. This is bounded package evidence, not runtime overlay equivalence or
image-wide completeness. It does not change the publisher's promotion hold.
"""

# ruff: noqa: INP001
import argparse
import json
import math
import os
import re
import resource
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
from collections import Counter, defaultdict
from contextlib import suppress
from pathlib import Path
from types import SimpleNamespace

from scripts.check_go_sbom_coverage import digest_file
from scripts.check_sandbox_attestations import (
    COVERAGE_TYPE,
    PROV_TYPE,
    QUAL_TYPE,
    SBOM_TYPE,
    accepted,
)
from scripts.check_sandbox_sbom_coverage import (
    MAX_APPS_BYTES,
    MAX_CONFIG_BYTES,
    MAX_MANIFEST_BYTES,
    MAX_SBOM_BYTES,
    build_go_receipts,
    load_applications,
    read_regular,
    require,
    sha256,
    validate_go_tool,
    validate_inventory,
    validate_shared_identity,
)
from scripts.check_sbom_inventory import (
    MAX_GO_BINARY_BYTES,
    MAX_METADATA_BYTES,
    MAX_TOTAL_GO_BINARY_BYTES,
    MAX_TOTAL_METADATA_BYTES,
    guarded_scope,
    metadata_kind,
    scan_rootfs,
)
from scripts.model_oci_metadata_overlay import model_verified_image
from scripts.prepare_sandbox_sbom import describe_document_bytes
from scripts.verify_oci_layer_binding import (
    DIGEST,
    blob_file,
    metadata_blob,
    read_json,
    verify_layer,
)
from scripts.verify_sandbox_platform_index import platform_manifests


REPOSITORY = "ecryptoguru/lyrashield-engine"
IMAGE = "ghcr.io/ecryptoguru/lyrashield-sandbox"
MAX_AUTH_BYTES = 16 * 1024**2
MAX_SCOPED_TAR_BYTES = 3 * 1024**3
MAX_SECONDS = 1800
MAX_HELPER_ADDRESS_SPACE = 2 * 1024**3
MAX_FINAL_HEADERS = 200_000
GH_TOOL = Path("/usr/bin/gh")
GH_TOOL_SHA256 = "62c11fbaa08835168c3d1acf8a645ac6268a13a5682c73581388c9df0c622617"
GO_TOOL_SHA256 = "5f5eb6d0b2fb6aa0bb5d5f8c5f1c944e0de955c925f0111af92a9d8f79680b5b"
SOURCE_FILES = (
    "containers/go-tools/applications.json",
    "containers/go-tools/distro/applications.cdx.json",
)
LIMITATIONS = [
    "Only Debian status, declared Python/npm metadata roots and twelve pinned Go files",
    "Conservative OCI header model; unsupported changesets fail closed",
    "Header/link/package and Go parsers are shared with the bounded producer oracle",
    "No Linux runtime overlay, capability state or image-wide completeness proof",
    "No benchmark, adversarial robustness or production promotion qualification",
]


class BoundedTarOutput:
    """Bound every write, including a single large payload and tar padding."""

    def __init__(self, stream):
        self.stream = stream

    def write(self, data):
        require(
            self.stream.tell() + len(data) <= MAX_SCOPED_TAR_BYTES, "scoped archive exceeds bound"
        )
        return self.stream.write(data)


def trusted_tool(path, expected):
    """Protected source pin plus immutable-to-unprivileged-users host path."""
    require(path.is_absolute(), "trusted tool must be absolute")
    for parent in [path, *path.parents]:
        metadata = parent.lstat()
        require(
            not stat.S_ISLNK(metadata.st_mode)
            and metadata.st_uid == 0
            and metadata.st_mode & 0o022 == 0,
            "tool path is not protected",
        )
        require(
            stat.S_ISREG(metadata.st_mode) if parent == path else stat.S_ISDIR(metadata.st_mode),
            "invalid trusted tool path type",
        )
    require(digest_file(path) == expected, "protected tool checksum mismatch")
    return path


def read_blob(directory, digest, limit, size=None):
    require(isinstance(digest, str) and DIGEST.fullmatch(digest), "invalid blob identity")
    with blob_file(directory, digest) as source:
        data = source.read(limit + 1)
    require(0 < len(data) <= limit and sha256(data) == digest, "blob byte binding mismatch")
    require(size is None or len(data) == size, "blob size mismatch")
    return data


def verified_predicate(records, predicate_type, args):
    """Policy only. The CLI supplies stdout from successful live gh verification."""
    invocation = (
        f"https://github.com/{args.repo}/actions/runs/{args.run_id}/attempts/{args.run_attempt}"
    )
    require(isinstance(records, list) and len(records) <= 30, "invalid verified records")
    candidates = []
    for record in records:
        if not isinstance(record, dict):
            continue
        statement = (record.get("verificationResult") or {}).get("statement") or {}
        predicate = statement.get("predicate")
        if isinstance(predicate, dict) and accepted(
            [record],
            predicate_type=predicate_type,
            expected=predicate,
            args=args,
            invocation=invocation,
        ):
            candidates.append(predicate)
    require(len(candidates) == 1, "missing or ambiguous authenticated predicate")
    return candidates[0]


def bounded_command(command, limit, timeout):
    """No pipes or shell; reap the direct child before removing its private output."""
    with tempfile.TemporaryFile() as output:

        def bounds():
            resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            if sys.platform.startswith("linux"):
                resource.setrlimit(resource.RLIMIT_AS, (MAX_HELPER_ADDRESS_SPACE,) * 2)
            cpu_seconds = max(1, math.ceil(timeout))
            resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds))

        # Single-threaded host gh/git commands; image payloads are never executed.
        child = subprocess.Popen(  # noqa: S603
            command,
            stdout=output,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            preexec_fn=bounds,  # noqa: PLW1509 - single-threaded POSIX CLI only
        )
        try:
            child.wait(timeout=timeout)
            require(child.returncode == 0, "trusted metadata command failed")
        except BaseException:
            with suppress(ProcessLookupError):
                os.killpg(child.pid, signal.SIGKILL)
            child.wait(timeout=10)
            raise
        require(output.tell() <= limit, "trusted metadata output exceeds bound")
        output.seek(0)
        return output.read(limit + 1)


def authenticate(index_file, args):
    require(
        sha256(read_regular(index_file, 65536)) == args.digest,
        "local index differs before authentication",
    )
    trusted_tool(GH_TOOL, GH_TOOL_SHA256)
    command = [
        str(GH_TOOL),
        "attestation",
        "verify",
        "oci://" + args.image + "@" + args.digest,
        "--bundle-from-oci",
        "--repo",
        args.repo,
        "--signer-workflow",
        args.repo + "/.github/workflows/publish-sandbox.yml",
        "--signer-digest",
        args.revision,
        "--source-digest",
        args.revision,
        "--source-ref",
        args.ref,
        "--deny-self-hosted-runners",
        "--format",
        "json",
    ]
    return {
        kind: verified_predicate(
            json.loads(bounded_command([*command, "--predicate-type", kind], MAX_AUTH_BYTES, 180)),
            kind,
            args,
        )
        for kind in (PROV_TYPE, QUAL_TYPE, SBOM_TYPE, COVERAGE_TYPE)
    }


def selected_payloads(model, applications):
    required = {entry["binary"].lstrip("/") for entry in applications}
    counts = Counter(id(node.inode) for node in model.entries.values() if node.inode is not None)
    selected, totals = {}, defaultdict(int)
    for path, node in model.entries.items():
        kind = metadata_kind(path)
        if kind is None and path not in required:
            continue
        if node.kind != "file":
            continue  # The full header inventory below rejects guarded links/missing files.
        require(node.inode is not None, "missing file extent")
        require(
            not node.hardlink_target and counts[id(node.inode)] == 1,
            "hardlink in bounded inventory scope",
        )
        maximum = MAX_GO_BINARY_BYTES if path in required else MAX_METADATA_BYTES
        require(0 <= node.inode.size <= maximum, "selected payload exceeds bound")
        totals["go" if path in required else "metadata"] += node.inode.size
        selected[path] = node.inode
    require(totals["go"] <= MAX_TOTAL_GO_BINARY_BYTES, "Go payload total exceeds bound")
    require(totals["metadata"] <= MAX_TOTAL_METADATA_BYTES, "metadata total exceeds bound")
    return selected


def capture_payloads(directory, manifest, config, selected, private_dir):
    """Reverify every layer while selecting final-image extents, never seek gzip."""
    grouped, paths = defaultdict(list), {}
    for index, (path, inode) in enumerate(selected.items()):
        local = private_dir / f"payload-{index}"
        paths[path] = local
        grouped[inode.source_layer].append((inode, local))
    total = 0
    for ordinal, (descriptor, diff_id) in enumerate(
        zip(
            manifest["layers"],
            config["rootfs"]["diff_ids"],
            strict=True,
        )
    ):
        extents = sorted(grouped[ordinal], key=lambda item: item[0].data_offset)
        position, copied, active = 0, defaultdict(int), 0
        output = None
        try:

            def receive(chunk, extents=extents, copied=copied):
                nonlocal position, active, output
                end = position + len(chunk)
                while active < len(extents):
                    inode, path = extents[active]
                    if inode.data_offset > end:
                        break
                    if output is None:
                        output = path.open("xb")
                        path.chmod(0o600)
                    start = max(position, inode.data_offset)
                    stop = min(end, inode.data_offset + inode.size)
                    if stop > start:
                        output.write(chunk[start - position : stop - position])
                        copied[id(inode)] += stop - start
                    if end < inode.data_offset + inode.size:
                        break
                    output.close()
                    output = None
                    active += 1
                position = end

            _, total = verify_layer(directory, descriptor, diff_id, total, receive)
            require(
                active == len(extents)
                and all(copied[id(inode)] == inode.size for inode, _ in extents),
                "selected extent incomplete",
            )
        finally:
            if output is not None:
                output.close()
    return paths


def scoped_archive(model, payloads, stream, applications):
    """Emit inert headers for all paths; retain bytes only within declared scope."""
    required = {entry["binary"].lstrip("/") for entry in applications}
    with tarfile.open(
        fileobj=BoundedTarOutput(stream), mode="w|", format=tarfile.PAX_FORMAT
    ) as archive:
        for path, node in model.entries.items():
            if not path:
                continue
            entry = tarfile.TarInfo(path)
            if node.kind == "dir":
                entry.type = tarfile.DIRTYPE
            elif node.kind == "symlink":
                entry.type = tarfile.SYMTYPE
                entry.linkname = node.target
            elif node.hardlink_target:
                entry.type = tarfile.LNKTYPE
                entry.linkname = node.hardlink_target
            else:
                require(node.kind == "file", "unsupported final header")
                if path in payloads:
                    entry.size = node.inode.size
                    with payloads[path].open("rb") as source:
                        archive.addfile(entry, source)
                    continue
                require(
                    metadata_kind(path) is None and path not in required,
                    "missing selected regular payload",
                )
                require(
                    guarded_scope(path, required) is None or node.inode is not None,
                    "invalid guarded header",
                )
            archive.addfile(entry)
            require(stream.tell() <= MAX_SCOPED_TAR_BYTES, "scoped archive exceeds bound")
    require(stream.tell() <= MAX_SCOPED_TAR_BYTES, "scoped archive exceeds bound")


def verify_platform(
    directory,
    architecture,
    qualification,
    sbom,
    coverage,
    applications,
    go_tool,
    go_tool_digest,
    scratch,
    producer_receipts,
):
    validate_shared_identity(qualification, sbom)
    binding = sbom["platforms"][architecture]
    manifest_raw = read_blob(directory, binding["manifestDigest"], MAX_MANIFEST_BYTES)
    manifest = read_json(manifest_raw)
    require(manifest["config"]["digest"] == binding["configDigest"], "signed config differs")
    config = metadata_blob(
        directory, binding["configDigest"], MAX_CONFIG_BYTES, manifest["config"]["size"]
    )
    labels = (config.get("config") or {}).get("Labels") or {}
    require(
        labels.get("org.opencontainers.image.revision") == qualification["engineRevision"]
        and labels.get("org.opencontainers.image.source") == "https://github.com/" + REPOSITORY,
        "native source labels differ",
    )
    document_raw = read_blob(directory, binding["documentDigest"], MAX_SBOM_BYTES, binding["size"])
    require(
        describe_document_bytes(
            document_raw,
            binding["filename"],
            IMAGE,
            architecture,
            binding["manifestDigest"],
            binding["configDigest"],
        )
        == binding,
        "SPDX signed root binding differs",
    )
    document = read_json(document_raw)
    expected = coverage["platforms"][architecture]
    receipt_raw = read_regular(producer_receipts / architecture / "receipt.json", MAX_AUTH_BYTES)
    require(sha256(receipt_raw) == expected["receiptDigest"], "signed receipt digest differs")
    producer = read_json(receipt_raw)
    require(
        producer.get("goToolSha256") == GO_TOOL_SHA256,
        "producer inspector differs from protected tool policy",
    )
    model = model_verified_image(
        directory,
        binding["manifestDigest"],
        "linux/" + architecture,
        linux_literal_paths=True,
        max_entries=MAX_FINAL_HEADERS,
    )
    require(model.config_digest == binding["configDigest"], "model configuration differs")
    require(
        model.runtime_equivalent is False and model.release_qualified is False,
        "unsupported model authority",
    )
    with tempfile.TemporaryDirectory(prefix="inventory-", dir=scratch) as temporary:
        private = Path(temporary)
        captures = private / "captures"
        captures.mkdir(mode=0o700)
        payloads = capture_payloads(
            directory, manifest, config, selected_payloads(model, applications), private
        )
        with tempfile.TemporaryFile(dir=private) as stream:
            scoped_archive(model, payloads, stream, applications)
            stream.seek(0)
            observed = scan_rootfs(stream, [entry["binary"] for entry in applications], captures)
        require(not observed["unresolved"], "bounded header inventory is incomplete")
        validate_inventory(observed["inventory"], document)
        go, _ = build_go_receipts(
            applications,
            observed["captures"],
            document,
            architecture,
            go_tool,
            go_tool_digest,
            scratch=private,
            max_tool_address_space=MAX_HELPER_ADDRESS_SPACE,
        )
        counts = {kind: len(values) for kind, values in observed["inventory"].items()}
        counts["goApplications"] = len(go)
        require(
            counts == producer["inventoryCounts"]
            and go == producer["goApplications"] == expected["goApplications"],
            "independent inventory differs from signed producer receipt",
        )
        require(
            expected["manifestDigest"] == binding["manifestDigest"]
            and expected["configDigest"] == binding["configDigest"]
            and expected["spdxDocumentDigest"] == binding["documentDigest"],
            "signed coverage platform identity differs",
        )
        return {
            "manifestDigest": binding["manifestDigest"],
            "configDigest": binding["configDigest"],
            "spdxDocumentDigest": binding["documentDigest"],
            "inventoryCounts": counts,
            "goApplications": go,
            "layers": len(model.layers),
            "finalHeaders": len(model.entries),
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("blobs", "source-repository", "scratch", "go-tool", "output", "producer-receipts"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("index-digest", "revision", "run-id", "run-attempt"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    require(re.fullmatch(r"[0-9a-f]{40}", args.revision), "invalid source revision")
    require(
        re.fullmatch(r"[1-9][0-9]*", args.run_id)
        and re.fullmatch(r"[1-9][0-9]*", args.run_attempt),
        "invalid run identity",
    )
    require(DIGEST.fullmatch(args.index_digest), "invalid index identity")
    require(
        args.scratch.is_dir()
        and args.scratch.stat().st_uid == os.getuid()
        and args.scratch.stat().st_mode & 0o777 == 0o700
        and not args.scratch.is_symlink(),
        "scratch must be private and owned",
    )
    require(shutil.disk_usage(args.scratch).free >= 8 * 1024**3, "insufficient scratch space")
    policy = SimpleNamespace(
        repo=REPOSITORY,
        image=IMAGE,
        ref="refs/heads/main",
        revision=args.revision,
        digest=args.index_digest,
        run_id=args.run_id,
        run_attempt=args.run_attempt,
    )
    directory = os.open(args.blobs, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        index_raw = read_blob(directory, args.index_digest, 65536)
        with tempfile.TemporaryDirectory(prefix="auth-", dir=args.scratch) as temporary:
            private = Path(temporary)
            index_file = private / "index.json"
            index_file.write_bytes(index_raw)
            verified = authenticate(index_file, policy)
            qualification, sbom, coverage = (
                verified[kind] for kind in (QUAL_TYPE, SBOM_TYPE, COVERAGE_TYPE)
            )
            for predicate in (qualification, sbom, coverage):
                require(
                    predicate.get("engineRevision") == args.revision
                    and predicate.get("workflowRevision") == args.revision
                    and predicate.get("runId") == args.run_id
                    and predicate.get("runAttempt") == args.run_attempt
                    and predicate.get("indexDigest") == args.index_digest,
                    "authenticated source/run binding mismatch",
                )
            platforms, _ = platform_manifests(read_json(index_raw))
            require(
                coverage.get("schema") == "lyrashield.sandbox.sbom-coverage.v1"
                and set(coverage.get("platforms", {})) == {"amd64", "arm64"},
                "invalid signed coverage schema",
            )
            for digest, media, size in platforms.values():
                child = read_blob(directory, digest, MAX_MANIFEST_BYTES, size)
                require(
                    read_json(child).get("mediaType") == media,
                    "native index descriptor media type differs",
                )
            require(
                {arch: item[0] for arch, item in platforms.items()}
                == qualification["platformManifests"],
                "signed native index differs",
            )
            source_hashes, files = {}, []
            for index, source in enumerate(SOURCE_FILES):
                raw = bounded_command(
                    [
                        "/usr/bin/git",
                        "--no-replace-objects",
                        "-C",
                        str(args.source_repository),
                        "show",
                        args.revision + ":" + source,
                    ],
                    MAX_APPS_BYTES,
                    30,
                )
                path = private / f"source-{index}.json"
                path.write_bytes(raw)
                source_hashes[source] = sha256(raw)
                files.append(path)
            applications = load_applications(*files)
            for architecture in ("amd64", "arm64"):
                require(
                    coverage["platforms"][architecture].get("goToolSha256") == GO_TOOL_SHA256,
                    "signed Go tool provenance differs from protected policy",
                )
            trusted_tool(args.go_tool, GO_TOOL_SHA256)
            tool_digest = validate_go_tool(args.go_tool, GO_TOOL_SHA256)
            results = {
                arch: verify_platform(
                    directory,
                    arch,
                    qualification,
                    sbom,
                    coverage,
                    applications,
                    args.go_tool,
                    tool_digest,
                    args.scratch,
                    args.producer_receipts,
                )
                for arch in ("amd64", "arm64")
            }
        receipt = {
            "schema": "lyrashield.sandbox.independent-package-inventory.v1",
            "status": "bounded_scope_matched",
            "indexDigest": args.index_digest,
            "engineRevision": args.revision,
            "workflowRevision": args.revision,
            "image": IMAGE,
            "runId": args.run_id,
            "runAttempt": args.run_attempt,
            "sourceFiles": source_hashes,
            "goToolSha256": tool_digest,
            "ghToolSha256": GH_TOOL_SHA256,
            "limits": {
                "finalHeaders": MAX_FINAL_HEADERS,
                "scopedArchiveBytes": MAX_SCOPED_TAR_BYTES,
                "individualMetadataBytes": MAX_METADATA_BYTES,
                "metadataBytes": MAX_TOTAL_METADATA_BYTES,
                "individualGoBinaryBytes": MAX_GO_BINARY_BYTES,
                "totalGoBinaryBytes": MAX_TOTAL_GO_BINARY_BYTES,
                "processingSeconds": MAX_SECONDS,
            },
            "platforms": results,
            "limitations": LIMITATIONS,
            "releaseQualified": False,
        }
        with args.output.open("x") as output:
            json.dump(receipt, output, sort_keys=True, separators=(",", ":"))
            output.write("\n")
    finally:
        os.close(directory)


if __name__ == "__main__":

    def timeout(_signum, _frame):
        raise TimeoutError("independent inventory deadline exceeded")

    signal.signal(signal.SIGALRM, timeout)
    signal.alarm(MAX_SECONDS)
    try:
        main()
    finally:
        signal.alarm(0)
