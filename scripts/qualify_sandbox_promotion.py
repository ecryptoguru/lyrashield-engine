"""Authenticate bounded package evidence before promoting an exact sandbox index.

This gate never reconstructs a coverage claim from caller-supplied positive fields.
It consumes the original held publisher and separately signed hosted inventory.
"""

# ruff: noqa: INP001
import argparse
import io
import json
import os
import re
import sys
import tempfile
import zipfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from urllib.error import HTTPError
from urllib.request import Request

from scripts.acquire_sandbox_inventory import REGISTRY, Registry, api, fetch_receipts
from scripts.bind_sandbox_inventory import RESOURCE_LIMITS, VERIFIER_FILES, WORKFLOW
from scripts.check_sandbox_sbom_coverage import (
    read_regular,
    require,
    sha256,
    validate_shared_identity,
)
from scripts.verify_oci_layer_binding import DIGEST, read_json
from scripts.verify_sandbox_package_inventory import (
    COVERAGE_TYPE,
    GH_TOOL,
    GH_TOOL_SHA256,
    GO_TOOL_SHA256,
    IMAGE,
    LIMITATIONS,
    MAX_AUTH_BYTES,
    QUAL_TYPE,
    REPOSITORY,
    SBOM_TYPE,
    SOURCE_FILES,
    authenticate,
    bounded_command,
    private_command_scratch,
    trusted_tool,
)
from scripts.verify_sandbox_platform_index import platform_manifests


PROMOTION_WORKFLOW = ".github/workflows/promote-qualified-sandbox.yml"
INVENTORY_TYPE = "https://lyrashieldai.com/attestations/sandbox-independent-inventory/v1"
PUBLISHER_WORKFLOW_BLOB = "77361a87c6c7b4e2b11c79a69b9e574fd326a0d0"
REVISION = re.compile(r"[0-9a-f]{40}")
IDENTIFIER = re.compile(r"[1-9][0-9]{0,19}")


def selector(value: object) -> dict[str, str]:
    expected = {
        "indexDigest",
        "engineRevision",
        "publisherRunId",
        "publisherAttempt",
        "inventoryRunId",
        "inventoryAttempt",
        "verifierRevision",
        "artifactId",
        "artifactDigest",
        "receiptDigest",
    }
    require(isinstance(value, dict) and set(value) == expected, "invalid promotion selector")
    record = cast("dict[str, str]", value)
    for name in expected:
        pattern = (
            DIGEST
            if name.endswith("Digest")
            else REVISION
            if name.endswith("Revision")
            else IDENTIFIER
        )
        require(
            isinstance(record[name], str) and pattern.fullmatch(record[name]),
            "invalid selector identity",
        )
    return record


def git(repository: Path, *arguments: str) -> bytes:
    return cast(
        "bytes",
        bounded_command(
            ["/usr/bin/git", "--no-replace-objects", "-C", str(repository), *arguments],
            2 * 1024**2,
            30,
        ),
    )


def current_source(repository: Path, environment: Mapping[str, str]) -> str:
    require(
        environment.get("GITHUB_REPOSITORY") == REPOSITORY
        and environment.get("GITHUB_REPOSITORY_ID") == "1297157605"
        and environment.get("GITHUB_REPOSITORY_OWNER_ID") == "116722580"
        and environment.get("GITHUB_REF") == "refs/heads/main"
        and environment.get("GITHUB_WORKFLOW_REF")
        == REPOSITORY + "/" + PROMOTION_WORKFLOW + "@refs/heads/main",
        "unexpected promotion workflow identity",
    )
    revision = environment.get("GITHUB_SHA", "")
    require(REVISION.fullmatch(revision), "invalid current revision")
    require(git(repository, "rev-parse", "HEAD").decode().strip() == revision, "checkout changed")
    for source in (*VERIFIER_FILES, PROMOTION_WORKFLOW, "scripts/qualify_sandbox_promotion.py"):
        require(
            read_regular(repository / source, 2 * 1024**2)
            == git(repository, "show", revision + ":" + source),
            "executed promotion source differs from current qualified commit",
        )
    require(read_json(api("git/ref/heads/main"))["object"]["sha"] == revision, "main advanced")
    return revision


def qualified_ci(revision: str) -> dict[str, str]:
    data = read_json(
        api("actions/workflows/ci.yml/runs?event=push&head_sha=" + revision + "&per_page=100")
    )
    runs = data.get("workflow_runs")
    require(isinstance(runs, list) and 0 < len(runs) <= 100, "CI missing")
    matches = [
        run
        for run in runs
        if run.get("head_sha") == revision
        and run.get("head_branch") == "main"
        and run.get("event") == "push"
    ]
    require(matches and all(type(run.get("id")) is int for run in matches), "CI identity missing")
    latest = max(matches, key=lambda run: run["id"])
    require(
        latest.get("status") == "completed" and latest.get("conclusion") == "success",
        "latest main CI unsuccessful",
    )
    return {"runId": str(latest["id"]), "runAttempt": str(latest["run_attempt"])}


def inventory_run(value: dict[str, str]) -> None:
    run_id, attempt = value["inventoryRunId"], value["inventoryAttempt"]
    run = read_json(api("actions/runs/" + run_id))
    require(
        str(run.get("id")) == run_id
        and str(run.get("run_attempt")) == attempt
        and run.get("status") == "completed"
        and run.get("conclusion") == "success"
        and run.get("event") == "workflow_dispatch"
        and run.get("head_branch") == "main"
        and run.get("head_sha") == value["verifierRevision"]
        and run.get("path") == WORKFLOW
        and run.get("repository", {}).get("id") == 1297157605
        and run.get("head_repository", {}).get("id") == 1297157605,
        "independent run identity differs",
    )
    jobs = read_json(api("actions/runs/" + run_id + "/attempts/" + attempt + "/jobs?per_page=100"))
    require(
        jobs.get("total_count") == 2 and len(jobs.get("jobs", [])) == 2, "independent jobs differ"
    )
    require(
        {job.get("name") for job in jobs["jobs"]}
        == {"independent-inventory", "publish-inventory-attestation"},
        "independent jobs missing",
    )
    for job in jobs["jobs"]:
        require(
            job.get("status") == "completed" and job.get("conclusion") == "success",
            "independent job unsuccessful",
        )
        steps = job.get("steps")
        require(
            isinstance(steps, list)
            and steps
            and all(
                step.get("status") == "completed" and step.get("conclusion") == "success"
                for step in steps
            ),
            "independent step unsuccessful",
        )


def inventory_artifact(value: dict[str, str]) -> dict[str, Any]:
    item = read_json(api("actions/artifacts/" + value["artifactId"]))
    origin = item.get("workflow_run") or {}
    require(
        str(item.get("id")) == value["artifactId"]
        and item.get("expired") is False
        and item.get("name")
        == "independent-sandbox-inventory-"
        + value["inventoryRunId"]
        + "-"
        + value["inventoryAttempt"]
        and item.get("digest") == value["artifactDigest"]
        and type(item.get("size_in_bytes")) is int
        and 0 < item["size_in_bytes"] <= MAX_AUTH_BYTES + 65536
        and str(origin.get("id")) == value["inventoryRunId"]
        and origin.get("head_sha") == value["verifierRevision"]
        and origin.get("head_branch") == "main"
        and origin.get("repository_id") == 1297157605
        and origin.get("head_repository_id") == 1297157605,
        "independent artifact identity differs",
    )
    raw = api("actions/artifacts/" + value["artifactId"] + "/zip", MAX_AUTH_BYTES + 65536)
    require(
        len(raw) == item["size_in_bytes"] and sha256(raw) == value["artifactDigest"],
        "independent archive differs",
    )
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        entries = archive.infolist()
        require(
            len(entries) == 1
            and entries[0].filename == "independent-sandbox-inventory.json"
            and 0 < entries[0].file_size <= MAX_AUTH_BYTES,
            "unexpected independent archive contents",
        )
        receipt = archive.read(entries[0])
    require(sha256(receipt) == value["receiptDigest"], "independent receipt differs")
    return cast("dict[str, Any]", read_json(receipt))


def authenticate_inventory(value: dict[str, str], receipt: dict[str, Any]) -> None:
    command = [
        str(GH_TOOL),
        "attestation",
        "verify",
        "oci://" + IMAGE + "@" + value["indexDigest"],
        "--bundle-from-oci",
        "--repo",
        REPOSITORY,
        "--signer-workflow",
        REPOSITORY + "/" + WORKFLOW,
        "--signer-digest",
        value["verifierRevision"],
        "--source-digest",
        value["verifierRevision"],
        "--source-ref",
        "refs/heads/main",
        "--deny-self-hosted-runners",
        "--predicate-type",
        INVENTORY_TYPE,
        "--format",
        "json",
    ]
    records = json.loads(bounded_command(command, MAX_AUTH_BYTES, 180))
    require(isinstance(records, list) and len(records) <= 30, "invalid inventory attestations")
    expected_certificate = {
        "issuer": "https://token.actions.githubusercontent.com",
        "buildSignerURI": "https://github.com/" + REPOSITORY + "/" + WORKFLOW + "@refs/heads/main",
        "buildSignerDigest": value["verifierRevision"],
        "sourceRepositoryURI": "https://github.com/" + REPOSITORY,
        "sourceRepositoryDigest": value["verifierRevision"],
        "sourceRepositoryRef": "refs/heads/main",
        "runnerEnvironment": "github-hosted",
        "runInvocationURI": "https://github.com/"
        + REPOSITORY
        + "/actions/runs/"
        + value["inventoryRunId"]
        + "/attempts/"
        + value["inventoryAttempt"],
    }
    accepted = []
    for record in records:
        result = record.get("verificationResult") or {}
        certificate = (result.get("signature") or {}).get("certificate") or {}
        statement = result.get("statement") or {}
        if (
            all(certificate.get(key) == expected for key, expected in expected_certificate.items())
            and statement.get("_type") == "https://in-toto.io/Statement/v1"
            and statement.get("predicateType") == INVENTORY_TYPE
            and statement.get("subject")
            == [{"name": IMAGE, "digest": {"sha256": value["indexDigest"][7:]}}]
            and statement.get("predicate") == receipt
        ):
            accepted.append(receipt)
    require(len(accepted) == 1, "inventory attestation missing or ambiguous")


def source_hashes(repository: Path, revision: str, files: Sequence[str]) -> dict[str, str]:
    return {name: sha256(git(repository, "show", revision + ":" + name)) for name in files}


def validate_receipt(
    value: dict[str, str],
    receipt: dict[str, Any],
    repository: Path,
    publication: dict[str, Any],
    receipts: Path,
) -> None:
    require(
        receipt.get("schema") == "lyrashield.sandbox.independent-package-inventory.v1"
        and receipt.get("status") == "bounded_scope_matched"
        and receipt.get("releaseQualified") is False
        and receipt.get("image") == IMAGE
        and receipt.get("indexDigest") == value["indexDigest"]
        and receipt.get("engineRevision")
        == receipt.get("workflowRevision")
        == value["engineRevision"]
        and receipt.get("runId") == value["publisherRunId"]
        and receipt.get("runAttempt") == value["publisherAttempt"]
        and receipt.get("limitations") == LIMITATIONS
        and receipt.get("ghToolSha256") == GH_TOOL_SHA256
        and receipt.get("goToolSha256") == GO_TOOL_SHA256,
        "bounded inventory selector or policy differs",
    )
    verifier = receipt.get("verifier") or {}
    approved_sources = source_hashes(
        repository, git(repository, "rev-parse", "HEAD").decode().strip(), VERIFIER_FILES
    )
    require(
        source_hashes(repository, value["verifierRevision"], VERIFIER_FILES) == approved_sources,
        "independent verifier implementation differs from reviewed consumer policy",
    )
    require(
        verifier
        == {
            "repositoryId": "1297157605",
            "ownerId": "116722580",
            "revision": value["verifierRevision"],
            "tree": git(repository, "rev-parse", value["verifierRevision"] + "^{tree}")
            .decode()
            .strip(),
            "workflow": WORKFLOW,
            "runId": value["inventoryRunId"],
            "runAttempt": value["inventoryAttempt"],
            "sourceFiles": source_hashes(repository, value["verifierRevision"], VERIFIER_FILES),
        },
        "independent verifier source differs",
    )
    require(
        receipt.get("sourceFiles")
        == source_hashes(repository, value["engineRevision"], SOURCE_FILES),
        "published application source differs",
    )
    require(
        all(
            receipt.get("limits", {}).get(name) == bound for name, bound in RESOURCE_LIMITS.items()
        ),
        "independent resource policy differs",
    )
    qualification, sbom, coverage = (
        publication[kind] for kind in (QUAL_TYPE, SBOM_TYPE, COVERAGE_TYPE)
    )
    validate_shared_identity(qualification, sbom)
    require(set(receipt.get("platforms", {})) == {"amd64", "arm64"}, "native inventory missing")
    for arch in ("amd64", "arm64"):
        observed, expected = receipt["platforms"][arch], coverage["platforms"][arch]
        producer = read_json(read_regular(receipts / arch / "receipt.json", MAX_AUTH_BYTES))
        require(
            observed["manifestDigest"]
            == expected["manifestDigest"]
            == qualification["platformManifests"][arch]
            and observed["configDigest"]
            == expected["configDigest"]
            == sbom["platforms"][arch]["configDigest"]
            and observed["spdxDocumentDigest"]
            == expected["spdxDocumentDigest"]
            == sbom["platforms"][arch]["documentDigest"]
            and observed["inventoryCounts"] == producer["inventoryCounts"]
            and observed["goApplications"]
            == producer["goApplications"]
            == expected["goApplications"],
            "native inventory does not match signed publisher evidence",
        )


def qualify(
    value: object, repository: Path, environment: Mapping[str, str], root: Path
) -> dict[str, Any]:
    value = selector(value)
    trusted_tool(GH_TOOL, GH_TOOL_SHA256)
    revision = current_source(repository, environment)
    ci = qualified_ci(revision)
    engine_ci = qualified_ci(value["engineRevision"])
    for source in (value["engineRevision"], value["verifierRevision"]):
        git(repository, "merge-base", "--is-ancestor", source, revision)
    require(
        git(
            repository,
            "rev-parse",
            value["engineRevision"] + ":.github/workflows/publish-sandbox.yml",
        )
        .decode()
        .strip()
        == PUBLISHER_WORKFLOW_BLOB,
        "unreviewed publisher",
    )
    inventory_run(value)
    receipt = inventory_artifact(value)
    authenticate_inventory(value, receipt)
    index_path = root / "index.json"
    Registry().fetch("manifests", value["indexDigest"], index_path, limit=65536)
    policy = SimpleNamespace(
        repo=REPOSITORY,
        image=IMAGE,
        ref="refs/heads/main",
        revision=value["engineRevision"],
        digest=value["indexDigest"],
        run_id=value["publisherRunId"],
        run_attempt=value["publisherAttempt"],
    )
    publication = authenticate(index_path, policy)
    for predicate in (publication[kind] for kind in (QUAL_TYPE, SBOM_TYPE, COVERAGE_TYPE)):
        require(
            predicate.get("engineRevision")
            == predicate.get("workflowRevision")
            == value["engineRevision"]
            and predicate.get("runId") == value["publisherRunId"]
            and predicate.get("runAttempt") == value["publisherAttempt"]
            and predicate.get("indexDigest") == value["indexDigest"],
            "publisher attestation identity differs",
        )
    platforms, _ = platform_manifests(read_json(index_path.read_bytes()))
    require(
        {arch: item[0] for arch, item in platforms.items()}
        == publication[QUAL_TYPE]["platformManifests"],
        "native index differs",
    )
    receipts = root / "publisher-receipts"
    fetch_receipts(
        value["publisherRunId"],
        value["publisherAttempt"],
        value["engineRevision"],
        publication[COVERAGE_TYPE],
        receipts,
    )
    validate_receipt(value, receipt, repository, publication, receipts)
    require(
        current_source(repository, environment) == revision, "main changed during qualification"
    )
    require(qualified_ci(revision) == ci, "CI changed during qualification")
    require(
        qualified_ci(value["engineRevision"]) == engine_ci,
        "engine CI changed during qualification",
    )
    return {
        "schema": "lyrashield.sandbox.promotion-inputs.v1",
        "selector": value,
        "promotionSource": revision,
        "ci": ci,
        "engineCi": engine_ci,
        "limitations": LIMITATIONS,
        "packageCoverage": "bounded_scope_matched",
        "imageWideCompleteness": False,
        "productionRuntimeQualified": False,
    }


def qualified_reference(registry: Registry, value: dict[str, str]) -> bool:
    request = Request(  # noqa: S310 - fixed HTTPS registry and validated full commit tag
        REGISTRY + "manifests/" + value["engineRevision"],
        headers={
            "Authorization": registry.authorization,
            "Accept": (
                "application/vnd.oci.image.index.v1+json, "
                "application/vnd.docker.distribution.manifest.list.v2+json"
            ),
        },
    )
    try:
        with registry.opener.open(request, timeout=30) as response:
            raw = response.read(65537)
        require(
            0 < len(raw) <= 65536 and sha256(raw) == value["indexDigest"],
            "existing revision tag conflicts",
        )
    except HTTPError as error:
        if error.code == 404:
            return False
        raise
    else:
        return True


def promote(
    result: dict[str, Any], repository: Path, environment: Mapping[str, str]
) -> dict[str, Any]:
    value = selector(result["selector"])
    registry = Registry()
    present = qualified_reference(registry, value)
    require(
        current_source(repository, environment) == result["promotionSource"],
        "main changed before promotion",
    )
    require(qualified_ci(result["promotionSource"]) == result["ci"], "CI changed before promotion")
    require(
        qualified_ci(value["engineRevision"]) == result["engineCi"],
        "engine CI changed before promotion",
    )
    if not present:
        bounded_command(
            [
                "/usr/bin/docker",
                "buildx",
                "imagetools",
                "create",
                "--tag",
                IMAGE + ":" + value["engineRevision"],
                IMAGE + "@" + value["indexDigest"],
            ],
            65536,
            120,
        )
    require(qualified_reference(registry, value), "revision tag not acknowledged")
    require(
        current_source(repository, environment) == result["promotionSource"],
        "main changed during promotion",
    )
    return {
        **result,
        "schema": "lyrashield.sandbox.promotion.v1",
        "status": "qualified_reference_recorded",
        "imageReference": IMAGE + "@" + value["indexDigest"],
        "revisionReference": IMAGE + ":" + value["engineRevision"],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--promote", action="store_true")
    args = parser.parse_args()
    try:
        args.output.lstat()
    except FileNotFoundError:
        pass
    else:
        raise FileExistsError("Sandbox promotion receipt already exists")
    require(len(os.environ.get("SANDBOX_PROMOTION_SELECTOR", "")) <= 4096, "selector too large")
    with (
        tempfile.TemporaryDirectory(
            prefix="sandbox-promotion-", dir=os.environ["RUNNER_TEMP"]
        ) as temporary,
        private_command_scratch(Path(temporary)),
    ):
        result = qualify(
            read_json(os.environ["SANDBOX_PROMOTION_SELECTOR"].encode()),
            Path(os.environ["GITHUB_WORKSPACE"]),
            os.environ,
            Path(temporary),
        )
        if args.promote:
            pending = args.output.with_name(args.output.name + ".pending.json")
            with pending.open("x") as output:
                json.dump(result, output, sort_keys=True, separators=(",", ":"))
                output.write("\n")
            try:
                result = promote(result, Path(os.environ["GITHUB_WORKSPACE"]), os.environ)
                with args.output.open("x") as output:
                    json.dump(result, output, sort_keys=True, separators=(",", ":"))
                    output.write("\n")
            except BaseException:
                with args.output.with_name(args.output.name + ".unconfirmed.json").open(
                    "x"
                ) as output:
                    json.dump(
                        {
                            "schema": "lyrashield.sandbox.promotion-outcome.v1",
                            "outcome": "UNKNOWN",
                            "pendingReceiptDigest": sha256(pending.read_bytes()),
                        },
                        output,
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                    output.write("\n")
                raise
    if not args.promote:
        with args.output.open("x") as output:
            json.dump(result, output, sort_keys=True, separators=(",", ":"))
            output.write("\n")
    with Path(os.environ["GITHUB_OUTPUT"]).open("a") as output:
        output.write("index_digest=" + result["selector"]["indexDigest"] + "\n")
        output.write("engine_revision=" + result["selector"]["engineRevision"] + "\n")


if __name__ == "__main__":
    try:
        main()
    except Exception:  # noqa: BLE001 - never expose arbitrary receipt bodies or credentials
        sys.stderr.write("Sandbox promotion outcome unconfirmed; inspect retained receipts.\n")
        sys.exit(1)
