"""Bind measured inventory to the immutable hosted verifier before attestation."""

# ruff: noqa: INP001
import argparse
import json
import os
import re
import shutil
import signal
import sys
import tempfile
from pathlib import Path

from scripts.acquire_sandbox_inventory import (
    VERIFIER_ADDRESS_SPACE,
    VERIFIER_CPU_SECONDS,
    VERIFIER_FDS,
    VERIFIER_WALL_SECONDS,
    apply_process_limits,
)
from scripts.check_sandbox_sbom_coverage import read_regular, require, sha256
from scripts.verify_oci_layer_binding import read_json
from scripts.verify_sandbox_package_inventory import (
    MAX_HELPER_ADDRESS_SPACE,
    bounded_command,
    private_command_scratch,
)


WORKFLOW = ".github/workflows/verify-sandbox-inventory.yml"
VERIFIER_FILES = (
    WORKFLOW,
    "scripts/acquire_sandbox_inventory.py",
    "scripts/bind_sandbox_inventory.py",
    "scripts/catalog_pax_capability_headers.py",
    "scripts/check_go_sbom_coverage.py",
    "scripts/check_sandbox_attestations.py",
    "scripts/check_sandbox_sbom_coverage.py",
    "scripts/check_sbom_inventory.py",
    "scripts/model_oci_metadata_overlay.py",
    "scripts/prepare_independent_inventory_tools.sh",
    "scripts/prepare_sandbox_sbom.py",
    "scripts/probe_pax_capability.py",
    "scripts/reconstruct_oci_layers.py",
    "scripts/sandbox_sbom_go.py",
    "scripts/spool_verified_oci_layer.py",
    "scripts/verify_oci_layer_binding.py",
    "scripts/verify_pax_capability_stream.py",
    "scripts/verify_sandbox_package_inventory.py",
    "scripts/verify_sandbox_platform_index.py",
)
RESOURCE_LIMITS = {
    "verifierAddressSpaceBytes": VERIFIER_ADDRESS_SPACE,
    "helperAddressSpaceBytes": MAX_HELPER_ADDRESS_SPACE,
    "verifierCpuSeconds": VERIFIER_CPU_SECONDS,
    "verifierFileDescriptors": VERIFIER_FDS,
    "verifierWallSeconds": VERIFIER_WALL_SECONDS,
}


def git(repository, *arguments):
    return bounded_command(
        ["/usr/bin/git", "--no-replace-objects", "-C", str(repository), *arguments],
        2 * 1024**2,
        30,
    )


def bind(receipt, repository, environment):
    require(
        environment.get("GITHUB_REPOSITORY") == "ecryptoguru/lyrashield-engine"
        and environment.get("GITHUB_REPOSITORY_ID") == "1297157605"
        and environment.get("GITHUB_REPOSITORY_OWNER_ID") == "116722580"
        and environment.get("GITHUB_REF") == "refs/heads/main"
        and environment.get("GITHUB_WORKFLOW_REF")
        == "ecryptoguru/lyrashield-engine/" + WORKFLOW + "@refs/heads/main",
        "unexpected hosted verifier identity",
    )
    revision = environment.get("GITHUB_SHA", "")
    run_id = environment.get("GITHUB_RUN_ID", "")
    attempt = environment.get("GITHUB_RUN_ATTEMPT", "")
    require(
        re.fullmatch(r"[0-9a-f]{40}", revision)
        and re.fullmatch(r"[1-9][0-9]{0,19}", run_id)
        and re.fullmatch(r"[1-9][0-9]{0,19}", attempt),
        "invalid hosted verifier revision or run",
    )
    require(git(repository, "rev-parse", "HEAD").decode().strip() == revision, "checkout differs")
    tree = git(repository, "rev-parse", revision + "^{tree}").decode().strip()
    require(re.fullmatch(r"[0-9a-f]{40}", tree), "invalid verifier tree")
    require(
        receipt.get("schema") == "lyrashield.sandbox.independent-package-inventory.v1"
        and receipt.get("status") == "bounded_scope_matched"
        and receipt.get("releaseQualified") is False
        and "verifier" not in receipt
        and isinstance(receipt.get("limits"), dict)
        and not set(receipt["limits"]) & set(RESOURCE_LIMITS),
        "unqualified inventory receipt required",
    )
    sources = {}
    for source in VERIFIER_FILES:
        committed = git(repository, "show", revision + ":" + source)
        require(
            read_regular(repository / source, 2 * 1024**2) == committed, "verifier source changed"
        )
        sources[source] = sha256(committed)
    return {
        **receipt,
        "limits": {**receipt["limits"], **RESOURCE_LIMITS},
        "verifier": {
            "repositoryId": "1297157605",
            "ownerId": "116722580",
            "revision": revision,
            "tree": tree,
            "workflow": WORKFLOW,
            "runId": run_id,
            "runAttempt": attempt,
            "sourceFiles": sources,
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--source-repository", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(
        prefix="inventory-bind-", dir=os.environ["RUNNER_TEMP"]
    ) as root:
        scratch = Path(root)
        require(shutil.disk_usage(scratch).free >= 32 * 1024**2, "insufficient binding scratch")
        with private_command_scratch(scratch):
            result = bind(
                read_json(read_regular(args.receipt, 16 * 1024**2)),
                args.source_repository,
                os.environ,
            )
    with args.output.open("x") as output:
        json.dump(result, output, sort_keys=True, separators=(",", ":"))
        output.write("\n")


if __name__ == "__main__":

    def timeout(_signum, _frame):
        raise TimeoutError("verifier identity binding deadline exceeded")

    signal.signal(signal.SIGALRM, timeout)
    signal.alarm(120)
    try:
        apply_process_limits()
        main()
    except Exception:  # noqa: BLE001 - do not expose receipt contents or paths
        sys.stderr.write("Independent inventory identity binding failed.\n")
        sys.exit(1)
    finally:
        signal.alarm(0)
