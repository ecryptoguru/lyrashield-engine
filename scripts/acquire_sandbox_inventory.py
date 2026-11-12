"""Acquire a signed sandbox publication for the independent OCI inventory verifier.

Registry content and producer receipts are data, never executed. All layer downloads
are planned only after authentication, byte binding and disk/size checks.
"""

# ruff: noqa: INP001
import argparse
import hashlib
import io
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from scripts.check_sandbox_attestations import COVERAGE_TYPE, QUAL_TYPE, SBOM_TYPE
from scripts.check_sandbox_sbom_coverage import MAX_SBOM_BYTES, validate_shared_identity
from scripts.prepare_sandbox_sbom import ARTIFACT_TYPE, build_predicate
from scripts.verify_oci_layer_binding import (
    DIGEST,
    MAX_CONFIG,
    MAX_MANIFEST,
    MEDIA,
    descriptor,
    read_json,
)
from scripts.verify_sandbox_package_inventory import (
    GH_TOOL,
    GH_TOOL_SHA256,
    IMAGE,
    REPOSITORY,
    authenticate,
    bounded_command,
    require,
    sha256,
    trusted_tool,
)
from scripts.verify_sandbox_platform_index import platform_manifests


REGISTRY = "https://ghcr.io/v2/ecryptoguru/lyrashield-sandbox/"
REGISTRY_AUTH_URL = (
    "https://ghcr.io/token?scope=repository:ecryptoguru/lyrashield-sandbox:pull&service=ghcr.io"
)
MAX_TOTAL = 6 * 1024**3
MAX_LAYER = 2 * 1024**3
SCRATCH = 8 * 1024**3
MAX_RECEIPT_ZIP = 16 * 1024**2
MAX_RECEIPT = 4 * 1024**2


class RegistryRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parts = urlsplit(newurl)
        require(
            parts.scheme == "https"
            and parts.hostname in {"ghcr.io", "pkg-containers.githubusercontent.com"}
            and not parts.username
            and not parts.password
            and parts.port in (None, 443),
            "untrusted registry redirect",
        )
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if redirected:
            redirected.remove_header("Authorization")
        return redirected


def write_verified(stream, path, digest, size=None, limit=None):
    require(isinstance(digest, str) and DIGEST.fullmatch(digest), "invalid digest")
    maximum = size if size is not None else limit
    require(type(maximum) is int and maximum > 0, "invalid byte bound")
    count, checksum = 0, hashlib.sha256()
    created = False
    try:
        with path.open("xb") as output:
            created = True
            path.chmod(0o600)
            while True:
                chunk = stream.read(min(1024 * 1024, maximum - count + 1))
                if not chunk:
                    break
                count += len(chunk)
                require(count <= maximum, "download exceeds bound")
                output.write(chunk)
                checksum.update(chunk)
        require(
            count > 0
            and (size is None or count == size)
            and "sha256:" + checksum.hexdigest() == digest,
            "download digest or size mismatch",
        )
    except BaseException:
        if created:
            path.unlink(missing_ok=True)
        raise


def extract_receipts(raw, platforms, root):
    require(len(raw) <= MAX_RECEIPT_ZIP, "artifact zip exceeds bound")
    root.mkdir(mode=0o700)
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        for arch in ("amd64", "arm64"):
            entries = [x for x in archive.infolist() if x.filename == arch + "/receipt.json"]
            require(len(entries) == 1, "missing or duplicate receipt")
            entry = entries[0]
            mode = entry.external_attr >> 16
            require(
                not entry.is_dir()
                and (stat.S_IFMT(mode) in (0, stat.S_IFREG))
                and 0 < entry.file_size <= MAX_RECEIPT,
                "invalid receipt entry",
            )
            (root / arch).mkdir(mode=0o700)
            with archive.open(entry) as source:
                write_verified(
                    source,
                    root / arch / "receipt.json",
                    platforms[arch]["receiptDigest"],
                    entry.file_size,
                )


def api(path, maximum=1024 * 1024):
    return bounded_command(
        [
            str(GH_TOOL),
            "api",
            "--hostname",
            "github.com",
            "-H",
            "X-GitHub-Api-Version: 2022-11-28",
            "repos/" + REPOSITORY + "/" + path,
        ],
        maximum,
        60,
    )


def verify_publisher_jobs(data):
    """Accept only the reviewed publisher's deliberate final promotion hold."""
    expected = {
        "Resolve qualified engine revision",
        "Build sandbox (amd64)",
        "Build sandbox (arm64)",
        "Publish qualified sandbox index",
    }
    jobs = data.get("jobs")
    require(
        data.get("total_count") == 4 and isinstance(jobs, list) and len(jobs) == 4,
        "unexpected publisher jobs",
    )
    require({job.get("name") for job in jobs} == expected, "publisher job names differ")
    required = (
        "Assemble and verify qualified platform index",
        "Generate per-platform SPDX SBOMs",
        "Attach and validate complete SBOM artifact",
        "Sign provenance for the immutable image digest",
        "Sign selected runtime and qualified platform binding",
        "Sign per-platform SBOM binding",
        "Verify signed sandbox publication",
        "Qualify bounded SBOM coverage on both native images",
        "Assemble bounded SBOM coverage predicate",
        "Sign bounded SBOM coverage qualification",
        "Verify signed sandbox publication coverage",
        "Upload bounded SBOM coverage evidence",
    )
    hold = "Hold promotion pending independent package coverage"
    skipped = {"Promote the smoke-qualified digest", "Record deployable immutable reference"}
    for job in jobs:
        publish = job["name"] == "Publish qualified sandbox index"
        require(
            job.get("status") == "completed"
            and job.get("conclusion") == ("failure" if publish else "success"),
            "publisher job failed",
        )
        steps = job.get("steps")
        require(isinstance(steps, list) and steps, "publisher steps missing")
        numbers = [step.get("number") for step in steps]
        require(
            all(type(number) is int for number in numbers) and numbers == sorted(set(numbers)),
            "publisher step order invalid",
        )
        names = [step.get("name") for step in steps]
        if publish:
            require(
                all(names.count(name) == 1 for name in (*required, hold, *skipped)),
                "publisher evidence or hold missing",
            )
            order = [names.index(name) for name in (*required, hold)]
            require(
                order == sorted(order)
                and all(names.index(name) > names.index(hold) for name in skipped),
                "publisher evidence order differs",
            )
        for step in steps:
            expected_conclusion = (
                "failure"
                if publish and step["name"] == hold
                else "skipped"
                if publish and step["name"] in skipped
                else "success"
            )
            require(
                step.get("status") == "completed" and step.get("conclusion") == expected_conclusion,
                "unexpected publisher step result",
            )


def fetch_receipts(run_id, attempt, revision, coverage, root):
    run = read_json(api("actions/runs/" + run_id + "/attempts/" + attempt))
    require(
        str(run.get("id")) == run_id
        and str(run.get("run_attempt")) == attempt
        and run.get("status") == "completed"
        and run.get("conclusion") == "failure"
        and run.get("event") == "workflow_dispatch"
        and run.get("head_branch") == "main"
        and run.get("head_sha") == revision
        and run.get("path") == ".github/workflows/publish-sandbox.yml"
        and run.get("repository", {}).get("id") == 1297157605
        and run.get("head_repository", {}).get("id") == 1297157605,
        "publisher run identity differs",
    )
    verify_publisher_jobs(
        read_json(api("actions/runs/" + run_id + "/attempts/" + attempt + "/jobs?per_page=100"))
    )
    records = read_json(api("actions/runs/" + run_id + "/artifacts?per_page=100"))
    require(
        type(records.get("total_count")) is int
        and records["total_count"] <= 100
        and isinstance(records.get("artifacts"), list),
        "ambiguous artifact list",
    )
    wanted = "sandbox-sbom-coverage-" + run_id + "-" + attempt
    matches = [x for x in records["artifacts"] if isinstance(x, dict) and x.get("name") == wanted]
    require(len(matches) == 1, "missing or duplicate coverage artifact")
    item = matches[0]
    require(
        type(item.get("id")) is int
        and item["id"] > 0
        and item.get("expired") is False
        and type(item.get("size_in_bytes")) is int
        and 0 < item["size_in_bytes"] <= MAX_RECEIPT_ZIP
        and isinstance(item.get("digest"), str)
        and DIGEST.fullmatch(item["digest"]),
        "invalid coverage artifact",
    )
    workflow = item.get("workflow_run") or {}
    require(
        workflow.get("id") == int(run_id)
        and workflow.get("head_sha") == revision
        and workflow.get("head_branch") == "main"
        and workflow.get("repository_id") == 1297157605
        and workflow.get("head_repository_id") == 1297157605,
        "coverage artifact source differs",
    )
    raw = api("actions/artifacts/" + str(item["id"]) + "/zip", MAX_RECEIPT_ZIP)
    require(
        len(raw) == item["size_in_bytes"] and sha256(raw) == item["digest"], "artifact zip differs"
    )
    extract_receipts(raw, coverage["platforms"], root)


class Registry:
    def __init__(self):
        self.opener = build_opener(RegistryRedirect())
        with self.opener.open(REGISTRY_AUTH_URL, timeout=30) as response:
            data = response.read(65537)
        require(len(data) <= 65536, "registry token response too large")
        token = read_json(data).get("token")
        require(
            isinstance(token, str) and 0 < len(token) <= 16384 and "\n" not in token,
            "invalid registry token",
        )
        self.authorization = "Bearer " + token

    def fetch(self, kind, digest, destination, size=None, limit=None):
        require(
            kind in ("manifests", "blobs") and isinstance(digest, str) and DIGEST.fullmatch(digest),
            "invalid registry object",
        )
        request = Request(  # noqa: S310 - fixed HTTPS registry and validated digest
            REGISTRY + kind + "/" + digest,
            headers={
                "Authorization": self.authorization,
                "Accept": (
                    "application/vnd.oci.image.index.v1+json, "
                    "application/vnd.oci.image.manifest.v1+json, "
                    "application/vnd.docker.distribution.manifest.list.v2+json, "
                    "application/vnd.docker.distribution.manifest.v2+json"
                ),
            },
        )
        with self.opener.open(request, timeout=60) as response:
            write_verified(response, destination, digest, size, limit)


def add_plan(plan, digest, size):
    require(digest not in plan or plan[digest] == size, "conflicting blob sizes")
    plan[digest] = size
    require(sum(plan.values()) <= MAX_TOTAL, "compressed image exceeds bound")


def prepare(args, root):  # noqa: PLR0915 - one linear fail-closed verification sequence
    require(
        re.fullmatch(r"[0-9a-f]{40}", args.revision)
        and DIGEST.fullmatch(args.index_digest)
        and re.fullmatch(r"[1-9][0-9]{0,19}", args.run_id)
        and re.fullmatch(r"[1-9][0-9]{0,19}", args.run_attempt),
        "invalid selector",
    )
    require(shutil.disk_usage(root).free >= SCRATCH + 1024**3, "insufficient initial disk")
    trusted_tool(GH_TOOL, GH_TOOL_SHA256)
    workflow_blob = bounded_command(
        [
            "/usr/bin/git",
            "--no-replace-objects",
            "-C",
            str(args.source_repository),
            "rev-parse",
            args.revision + ":.github/workflows/publish-sandbox.yml",
        ],
        128,
        30,
    ).strip()
    require(
        workflow_blob == b"77361a87c6c7b4e2b11c79a69b9e574fd326a0d0",
        "unreviewed publisher workflow",
    )
    blobs, scratch, receipts, docs = (
        root / name for name in ("blobs", "scratch", "receipts", "docs")
    )
    for path in (blobs, scratch, docs):
        path.mkdir(mode=0o700)
    registry = Registry()
    index_path = blobs / args.index_digest[7:]
    registry.fetch("manifests", args.index_digest, index_path, limit=65536)
    index_raw = index_path.read_bytes()
    index = read_json(index_raw)
    policy = SimpleNamespace(
        repo=REPOSITORY,
        image=IMAGE,
        ref="refs/heads/main",
        revision=args.revision,
        digest=args.index_digest,
        run_id=args.run_id,
        run_attempt=args.run_attempt,
    )
    verified = authenticate(index_path, policy)
    qualification, sbom, coverage = (verified[k] for k in (QUAL_TYPE, SBOM_TYPE, COVERAGE_TYPE))
    for predicate in (qualification, sbom, coverage):
        require(
            predicate.get("engineRevision") == args.revision
            and predicate.get("workflowRevision") == args.revision
            and predicate.get("runId") == args.run_id
            and predicate.get("runAttempt") == args.run_attempt
            and predicate.get("indexDigest") == args.index_digest,
            "signed publication identity differs",
        )
    validate_shared_identity(qualification, sbom)
    require(
        coverage.get("schema") == "lyrashield.sandbox.sbom-coverage.v1"
        and set(coverage.get("platforms", {})) == {"amd64", "arm64"},
        "invalid coverage",
    )
    platforms, _ = platform_manifests(index)
    require(
        {a: v[0] for a, v in platforms.items()} == qualification["platformManifests"],
        "signed platform mismatch",
    )
    fetch_receipts(args.run_id, args.run_attempt, args.revision, coverage, receipts)
    manifests, plan = {}, {}
    for arch in ("amd64", "arm64"):
        digest, media, size = platforms[arch]
        require(size <= MAX_MANIFEST, "native manifest too large")
        path = blobs / digest[7:]
        registry.fetch("manifests", digest, path, size=size)
        manifest = read_json(path.read_bytes())
        require(
            manifest.get("schemaVersion") == 2
            and manifest.get("mediaType") == media
            and media in MEDIA
            and "artifactType" not in manifest
            and "subject" not in manifest,
            "invalid image manifest",
        )
        config_type, layer_types = MEDIA[media]
        config_digest, config_size = descriptor(manifest.get("config"), {config_type}, MAX_CONFIG)
        require(config_digest == sbom["platforms"][arch]["configDigest"], "signed config mismatch")
        config_path = blobs / config_digest[7:]
        if not config_path.exists():
            registry.fetch("blobs", config_digest, config_path, size=config_size)
        config = read_json(config_path.read_bytes())
        labels = (config.get("config") or {}).get("Labels") or {}
        require(
            config.get("os") == "linux"
            and config.get("architecture") == arch
            and labels.get("org.opencontainers.image.revision") == args.revision
            and labels.get("org.opencontainers.image.source") == "https://github.com/" + REPOSITORY,
            "image config identity differs",
        )
        layers = manifest.get("layers")
        require(isinstance(layers, list) and 0 < len(layers) <= 128, "invalid layer list")
        for layer in layers:
            layer_digest, layer_size = descriptor(layer, layer_types, MAX_LAYER)
            add_plan(plan, layer_digest, layer_size)
        manifests[arch] = path
    artifact = sbom.get("artifact") or {}
    require(
        artifact.get("mediaType") == ARTIFACT_TYPE
        and isinstance(artifact.get("digest"), str)
        and DIGEST.fullmatch(artifact["digest"]),
        "invalid SBOM artifact",
    )
    artifact_path = root / "artifact.json"
    registry.fetch("manifests", artifact["digest"], artifact_path, limit=65536)
    for arch in ("amd64", "arm64"):
        item = sbom["platforms"][arch]
        require(item["size"] <= MAX_SBOM_BYTES, "SBOM too large")
        blob = blobs / item["documentDigest"][7:]
        registry.fetch("blobs", item["documentDigest"], blob, size=item["size"])
        os.link(blob, docs / item["filename"])
    metadata = {
        "containerimage.descriptor": {
            "digest": args.index_digest,
            "size": len(index_raw),
            "mediaType": index["mediaType"],
        }
    }
    reconstructed = build_predicate(
        qualification,
        metadata,
        artifact_path.read_bytes(),
        artifact["digest"],
        IMAGE,
        manifests,
        docs,
    )
    require(reconstructed == sbom, "signed SBOM artifact differs")
    require(
        shutil.disk_usage(root).free >= sum(plan.values()) + SCRATCH,
        "insufficient disk for layers and verification",
    )
    for digest, size in plan.items():
        registry.fetch("blobs", digest, blobs / digest[7:], size=size)
    return blobs, scratch, receipts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("index-digest", "revision", "run-id", "run-attempt"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--source-repository", type=Path, required=True)
    parser.add_argument("--go-tool", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(
        prefix="sandbox-inventory-", dir=os.environ["RUNNER_TEMP"]
    ) as temporary:
        root = Path(temporary)
        blobs, scratch, receipts = prepare(args, root)
        signal.alarm(0)  # The verifier has its own 30-minute process deadline.
        command = [
            sys.executable,
            "-m",
            "scripts.verify_sandbox_package_inventory",
            "--blobs",
            str(blobs),
            "--scratch",
            str(scratch),
            "--producer-receipts",
            str(receipts),
            "--source-repository",
            str(args.source_repository),
            "--go-tool",
            str(args.go_tool),
            "--output",
            str(args.output),
            "--index-digest",
            args.index_digest,
            "--revision",
            args.revision,
            "--run-id",
            args.run_id,
            "--run-attempt",
            args.run_attempt,
        ]
        subprocess.run(command, check=True, timeout=1810)  # noqa: S603 - fixed Python module and validated selector


if __name__ == "__main__":

    def timeout(_signum, _frame):
        raise TimeoutError("acquisition deadline exceeded")

    signal.signal(signal.SIGALRM, timeout)
    signal.alarm(1200)
    try:
        main()
    except Exception:  # noqa: BLE001 - suppress transport URLs and credentials
        # Registry redirect errors may contain signed URLs; never print them.
        sys.stderr.write("Independent inventory acquisition or verification failed.\n")
        sys.exit(1)
    finally:
        signal.alarm(0)
