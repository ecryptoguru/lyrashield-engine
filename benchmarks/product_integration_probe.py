"""Run an ephemeral, non-claimable product database and queue diagnostic."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from benchmarks.corpus.v3.validate import validate
from benchmarks.offline_sca_probe import digest
from benchmarks.run import BENCH_ROOT, PRODUCT_REPO


CORPUS = BENCH_ROOT / "corpus/v3"
RUNNER = BENCH_ROOT / "run_product_integration.mjs"
IMAGES = ("postgres:16-alpine", "redis:7-alpine")
HASH = re.compile(r"sha256:[0-9a-f]{64}")


def command(args: list[str], *, env: dict[str, str], cwd: Path) -> str:
    proc = subprocess.run(
        args, env=env, cwd=cwd, capture_output=True, text=True, timeout=20, check=False
    )
    if proc.returncode != 0:
        raise RuntimeError(f"local preflight command failed: {Path(args[0]).name}")
    return proc.stdout.strip()


def inputs() -> dict[str, str]:
    engine_paths = [
        CORPUS / "corpus.json",
        CORPUS / "adjudications.json",
        CORPUS / "held-out.json",
        CORPUS / "advisories/frozen.json",
        BENCH_ROOT / "profiles/v1/paths.json",
        BENCH_ROOT / "offline_sca_probe.py",
        RUNNER,
        Path(__file__),
    ]
    product_paths = [
        PRODUCT_REPO / ".github/scripts/run-user-scan-slot-runtime.mjs",
        PRODUCT_REPO / ".github/scripts/assert-vitest-file-counts.mjs",
        PRODUCT_REPO / "apps/worker/src/user-scan-slot.runtime.test.ts",
        PRODUCT_REPO / "apps/worker/src/user-scan-slot.fixture.test.ts",
        PRODUCT_REPO / "apps/worker/src/user-scan-slot.fixture.ts",
        PRODUCT_REPO / "packages/integrations/src/queue.ts",
        PRODUCT_REPO / "packages/db/prisma/schema.prisma",
        PRODUCT_REPO / "pnpm-lock.yaml",
    ]
    return {
        **{f"engine/{path.relative_to(BENCH_ROOT.parent)}": digest(path) for path in engine_paths},
        **{f"product/{path.relative_to(PRODUCT_REPO)}": digest(path) for path in product_paths},
    }


def git_output(repo: Path, *args: str) -> bytes:
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(Path.home()),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_OPTIONAL_LOCKS": "0",
    }
    return subprocess.run(
        ["git", "-c", "core.fsmonitor=false", *args],
        cwd=repo,
        env=env,
        capture_output=True,
        check=True,
        timeout=10,
    ).stdout


def source_state(repo: Path) -> dict[str, Any]:
    top = Path(git_output(repo, "rev-parse", "--show-toplevel").decode().strip()).resolve()
    if top != repo.resolve():
        raise RuntimeError("source identity mismatch: unexpected repository root")
    revision = git_output(repo, "rev-parse", "HEAD").decode().strip()
    paths = ["--", ".", ":(exclude)benchmarks/results"]
    diff = git_output(repo, "diff", "--binary", "HEAD", *paths)
    status = git_output(repo, "status", "--porcelain", *paths)
    return {
        "revision": revision,
        "trackedDiffSha256": hashlib.sha256(diff).hexdigest(),
        "dirty": bool(status),
    }


def current_product_main() -> str:
    try:
        revision = (
            git_output(PRODUCT_REPO, "rev-parse", "--verify", "refs/remotes/origin/main^{commit}")
            .decode()
            .strip()
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError(
            "product source identity mismatch: local origin/main unavailable"
        ) from exc
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise RuntimeError("product source identity mismatch: local origin/main unavailable")
    return revision


def cleanup_description(output: str) -> str:
    created = set(re.findall(r"^OWNED_CREATED:([0-9a-f]{64})$", output, re.MULTILINE))
    removed = set(re.findall(r"^OWNED_REMOVED:([0-9a-f]{64})$", output, re.MULTILINE))
    remaining = sorted(created - removed)
    if remaining:
        return "unconfirmed owned containers: " + ", ".join(remaining)
    if created:
        return "all logged owned containers removed"
    return "no owned container identity logged; cleanup unknown"


def write_sandbox_profile(temporary: Path) -> str:
    root = json.dumps(str(temporary.resolve()))
    return (
        "(version 1)\n(allow default)\n(deny file-write*)\n"
        f'(allow file-write* (subpath {root}) (literal "/dev/null"))\n'
    )


def run_child(args: list[str], *, env: dict[str, str], cwd: Path) -> tuple[str, str]:
    proc = subprocess.Popen(
        args, env=env, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    try:
        stdout, stderr = proc.communicate(timeout=480)
    except subprocess.TimeoutExpired:
        proc.send_signal(signal.SIGINT)
        try:
            stdout, stderr = proc.communicate(timeout=90)
        except subprocess.TimeoutExpired as exc:
            proc.kill()
            stdout, _stderr = proc.communicate()
            raise RuntimeError(f"fixture timed out; {cleanup_description(stdout)}") from exc
        raise RuntimeError(f"fixture timed out; {cleanup_description(stdout)}") from None
    if proc.returncode != 0:
        output_hash = hashlib.sha256((stdout + stderr).encode()).hexdigest()
        raise RuntimeError(
            f"fixture execution failed; {cleanup_description(stdout)}; output sha256 {output_hash}"
        )
    return stdout, stderr


def main() -> int:  # noqa: PLR0912, PLR0915 -- sequential fail-closed fixture orchestration
    try:
        docker = shutil.which("docker")
        if not docker:
            raise RuntimeError("local Docker executable unavailable")  # noqa: TRY301
        # Read only the configured local socket; never inherit Docker host/context overrides.
        home = str(Path.home())
        preflight_env = {"PATH": os.environ.get("PATH", ""), "HOME": home}
        host = json.loads(
            command(
                [docker, "context", "inspect", "--format", "{{json .Endpoints.docker.Host}}"],
                env=preflight_env,
                cwd=PRODUCT_REPO,
            )
        )
        if not isinstance(host, str) or not host.startswith("unix:///"):
            raise RuntimeError("local Unix Docker context required")  # noqa: TRY301
        product_source = source_state(PRODUCT_REPO)
        product_main = current_product_main()
        if product_source["dirty"] or product_source["revision"] != product_main:
            raise RuntimeError(  # noqa: TRY301
                "product source identity mismatch: "
                "a clean checkout of refreshed origin/main is required"
            )
        validate(CORPUS)
        sandbox = Path("/usr/bin/sandbox-exec")
        if sys.platform != "darwin" or not sandbox.is_file():
            raise RuntimeError("local write sandbox unavailable")  # noqa: TRY301
        node, pnpm = shutil.which("node"), shutil.which("pnpm")
        if not node or not pnpm:
            raise RuntimeError("local Node and pnpm executables required")  # noqa: TRY301
        node, pnpm, docker = (str(Path(path).resolve()) for path in (node, pnpm, docker))
        package = json.loads((PRODUCT_REPO / "package.json").read_text())["packageManager"]
        if not package.startswith("pnpm@"):
            raise RuntimeError("unsupported product package manager")  # noqa: TRY301
        corepack_home = Path(os.environ.get("COREPACK_HOME", Path(home) / ".cache/node/corepack"))
        pnpm_dir = corepack_home / "v1/pnpm" / package.removeprefix("pnpm@")
        pnpm_native = pnpm_dir / "pnpm-native"
        pnpm_entry = pnpm_dir / "bin/pnpm.mjs"
        if not pnpm_native.is_file() or not pnpm_entry.is_file():
            raise RuntimeError("required pnpm version is not cached for offline use")  # noqa: TRY301
        docker_env = {**preflight_env, "DOCKER_HOST": host}
        image_ids = {
            tag: command(
                [docker, "image", "inspect", "--format", "{{.Id}}", tag],
                env=docker_env,
                cwd=PRODUCT_REPO,
            )
            for tag in IMAGES
        }
        if any(not HASH.fullmatch(value) for value in image_ids.values()):
            raise RuntimeError("local fixture image identity unavailable")  # noqa: TRY301
        before_inputs = inputs()
        runtime = {
            "nodePath": node,
            "nodeSha256": digest(Path(node)),
            "pnpmPath": pnpm,
            "pnpmSha256": digest(Path(pnpm)),
            "pnpmNativePath": str(pnpm_native),
            "pnpmNativeSha256": digest(pnpm_native),
            "pnpmEntryPath": str(pnpm_entry),
            "pnpmEntrySha256": digest(pnpm_entry),
            "dockerPath": docker,
            "dockerSha256": digest(Path(docker)),
            "sandboxPath": str(sandbox),
            "sandboxSha256": digest(sandbox),
        }
        sources = {"engine": source_state(BENCH_ROOT.parent), "product": product_source}
        adjudication = json.loads((CORPUS / "adjudications.json").read_text())["review"]["status"]
        held_out = json.loads((CORPUS / "held-out.json").read_text())["status"]
        profiles = json.loads((BENCH_ROOT / "profiles/v1/paths.json").read_text())["profiles"]
        profile_status = next(p["status"] for p in profiles if p["id"] == "product_integration")
        short_tmp = "/tmp" if Path("/tmp").is_dir() else None  # noqa: S108 -- private mkdtemp below
        with tempfile.TemporaryDirectory(prefix="lyra-product-", dir=short_tmp) as directory:
            temporary = Path(directory)
            report = temporary / "vitest.json"
            child_env = {
                "PATH": f"{Path(node).parent}:/usr/bin:/bin",
                "HOME": directory,
                "TMPDIR": directory,
            }
            stdout, stderr = run_child(
                [
                    str(sandbox),
                    "-p",
                    write_sandbox_profile(temporary),
                    node,
                    str(RUNNER),
                    "--product",
                    str(PRODUCT_REPO),
                    "--docker",
                    docker,
                    "--docker-host",
                    host,
                    "--pnpm",
                    pnpm,
                    "--corepack-home",
                    str(corepack_home),
                    "--temporary",
                    directory,
                    "--report",
                    str(report),
                ],
                env=child_env,
                cwd=BENCH_ROOT.parent,
            )
            lines = [
                line.removeprefix("PRODUCTPROBE:")
                for line in stdout.splitlines()
                if line.startswith("PRODUCTPROBE:")
            ]
            if len(lines) != 1 or not report.is_file():
                raise RuntimeError("fixture result was incomplete")  # noqa: TRY301
            result = json.loads(lines[0])
            summary = result["report"]
            if summary != {"total": 14, "passed": 14, "failed": 0, "skipped": 0}:
                raise RuntimeError("fixture test results were incomplete")  # noqa: TRY301
            observed = result["observed"]
            images = []
            for tag, expected in image_ids.items():
                matching = [row for row in observed if row.get("imageTag") == tag]
                if not matching or any(row.get("imageId") != expected for row in matching):
                    raise RuntimeError("fixture container image identity changed")  # noqa: TRY301
                images.append(
                    {"tag": tag, "preflightImageId": expected, "observedImageId": expected}
                )
            if (
                current_product_main() != product_main
                or before_inputs != inputs()
                or sources
                != {
                    "engine": source_state(BENCH_ROOT.parent),
                    "product": source_state(PRODUCT_REPO),
                }
            ):
                raise RuntimeError("inputs or source changed during the diagnostic")  # noqa: TRY301
            if any(
                digest(Path(runtime[f"{name}Path"])) != runtime[f"{name}Sha256"]
                for name in ("node", "pnpm", "pnpmNative", "pnpmEntry", "docker", "sandbox")
            ):
                raise RuntimeError("runtime changed during the diagnostic")  # noqa: TRY301
            receipt: dict[str, Any] = {
                "schemaVersion": "lyrashield-local-product-diagnostic/1.0.0",
                "profile": "product_integration",
                "profileStatus": profile_status,
                "diagnosticStatus": "NOT_MEASURED",
                "claimStatus": "NOT_REPORTABLE",
                "adjudicationStatus": adjudication,
                "heldOutStatus": held_out,
                "sources": sources,
                "runtime": runtime,
                "images": images,
                "modelRoute": None,
                "productMainRef": product_main,
                "inputSha256": before_inputs,
                "result": summary,
                "reportSha256": digest(report),
                "outputSha256": hashlib.sha256((stdout + stderr).encode()).hexdigest(),
                "cleanup": "OWNED_SERVICES_REMOVED",
                "writeIsolation": "PRIVATE_TEMP_ONLY",
                "limitations": [
                    "Direct product database and queue tests only; no HTTP API, worker execution, "
                    "broker or supervisor path.",
                    "Product identity is checked against local origin/main; "
                    "refresh that ref before running.",
                    "No qualified image, model route, independent adjudication "
                    "or held-out corpus run.",
                    "Temporary test output and services are removed; hashes cannot be replayed "
                    "from retained artifacts.",
                    "The write sandbox does not establish OS-level network isolation.",
                ],
            }
    except (
        OSError,
        ValueError,
        KeyError,
        AssertionError,
        RuntimeError,
        subprocess.SubprocessError,
    ) as exc:
        print(f"Local product diagnostic failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(receipt, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
