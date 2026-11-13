"""Fixed image-owned verifier for guarded sandbox tool start admission.

Admission is the final trusted clock check, not a promise that the first tool
instruction runs with zero scheduler delay. The protected controller must arm
the independent whole-sandbox execution watchdog before dispatch and retain the
original guard/request and engine attachment on any uncertain acknowledgement.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import pwd
import stat
import sys
import time
from pathlib import Path
from typing import Any


if __package__:
    from lyrashield.runtime import controller_authority as authority
else:
    # The sandbox ships only these SDK-free files at this image-owned path.
    # Isolated Python never imports worker/workspace modules or environment paths.
    spec = importlib.util.spec_from_file_location(
        "_lyrashield_controller_authority",
        Path(__file__).with_name("controller_authority.py"),
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("Installed authority verifier unavailable")
    authority = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(authority)


TICKET_SCHEMA = "lyrashield-sandbox-start-ticket/1"
RESOURCE_SCHEMA = "lyrashield-prepared-sandbox-resource/1"
ADMISSION_PREFIX = b"LYRASHIELD_START_ADMISSION "
AUTHORITY_PATH = Path("/etc/lyrashield/runtime-authority.json")
RESOURCE_PATH = Path("/etc/lyrashield/sandbox-resource.json")
MAX_RECORD_BYTES = 128 * 1024
_FIELDS = frozenset(
    {
        "schema",
        "purpose",
        "scanId",
        "attemptId",
        "operationId",
        "authorityEpochId",
        "sandboxHandle",
        "guardId",
        "authorityChecksum",
        "actionChecksum",
        "requestId",
        "commandId",
        "containerId",
        "imageDigest",
        "manifestChecksum",
        "resourceDescriptorChecksum",
        "runtimePolicyDigest",
        "runtimeAuthorityChecksum",
        "command",
        "commandSha256",
        "clock",
        "executionDeadlineNs",
    }
)


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def checksum(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def protected_record(path: Path) -> tuple[dict[str, Any], bytes]:
    if not path.is_absolute() or ".." in path.parts:
        authority._reject()
    for parent in path.parents:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            authority._reject()
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or info.st_mode & 0o022
            or info.st_nlink != 1
        ):
            authority._reject()
        raw = os.read(descriptor, MAX_RECORD_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(raw) > MAX_RECORD_BYTES:
        authority._reject()
    record = json.loads(raw)
    if not isinstance(record, dict):
        authority._reject()
    return record, raw


def nanoseconds(value: Any) -> int:
    if (
        not isinstance(value, str)
        or not value.isascii()
        or not value.isdigit()
        or value.startswith("0")
        or len(value) > 19
    ):
        authority._reject()
    parsed = int(value)
    if parsed > 2**63 - 1:
        authority._reject()
    return parsed


def validate_start_ticket(  # noqa: PLR0912
    envelope: Any, runtime_authority: Any, resource: dict[str, Any], resource_raw: bytes
) -> dict[str, Any]:
    epoch = authority._text(resource.get("authorityEpochId"))
    root = authority.verify_runtime_authority(runtime_authority, epoch)
    ticket = authority._verify_envelope(envelope, root["sandboxGrantSigner"])
    if (
        set(ticket) != _FIELDS
        or ticket["schema"] != TICKET_SCHEMA
        or ticket["purpose"] != "sandbox-tool-start"
    ):
        authority._reject()
    if resource.get("schema") != RESOURCE_SCHEMA or ticket[
        "resourceDescriptorChecksum"
    ] != checksum(resource_raw):
        authority._reject()
    for field in (
        "scanId",
        "attemptId",
        "operationId",
        "authorityEpochId",
        "sandboxHandle",
        "containerId",
        "imageDigest",
        "manifestChecksum",
        "runtimePolicyDigest",
    ):
        if ticket[field] != resource.get(field):
            authority._reject()
        authority._text(ticket[field])
    if (
        ticket["imageDigest"] != root["sandboxDigest"]
        or ticket["runtimePolicyDigest"] != root["runtimePolicyDigest"]
    ):
        authority._reject()
    if ticket["runtimeAuthorityChecksum"] != checksum(runtime_authority["raw"].encode()):
        authority._reject()
    for field in ("guardId", "requestId", "commandId"):
        value = authority._text(ticket[field], max_length=128)
        if any(
            char not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
            for char in value
        ):
            authority._reject()
    for field in ("authorityChecksum", "actionChecksum", "commandSha256"):
        value = authority._text(ticket[field])
        if (
            not value.startswith("sha256:")
            or len(value) != 71
            or any(char not in "0123456789abcdef" for char in value[7:])
        ):
            authority._reject()
    command = ticket["command"]
    if not isinstance(command, dict) or set(command) != {"argv", "cwd", "user"}:
        authority._reject()
    if (
        command["user"] != "pentester"
        or command["cwd"] != "/workspace"
        or command["cwd"] != resource.get("workspaceRoot")
    ):
        authority._reject()
    argv = command["argv"]
    if not isinstance(argv, list) or not 1 <= len(argv) <= 256:
        authority._reject()
    for argument in argv:
        authority._text(argument)
    if (
        len(canonical(command)) > 32 * 1024
        or checksum(canonical(command)) != ticket["commandSha256"]
    ):
        authority._reject()
    clock = ticket["clock"]
    if (
        not isinstance(clock, dict)
        or set(clock) != {"id", "bootId", "timeNamespace", "issuedAtNs", "deadlineNs"}
        or clock["id"] != "CLOCK_MONOTONIC"
    ):
        authority._reject()
    if clock["bootId"] != Path("/proc/sys/kernel/random/boot_id").read_text().strip() or clock[
        "timeNamespace"
    ] != str(Path("/proc/self/ns/time").readlink()):
        authority._reject()
    issued = nanoseconds(clock["issuedAtNs"])
    deadline = nanoseconds(clock["deadlineNs"])
    execution_deadline = nanoseconds(ticket["executionDeadlineNs"])
    if (
        not issued < deadline < execution_deadline <= issued + 300_000_000_000
        or deadline - issued > 10_000_000_000
    ):
        authority._reject()
    return ticket


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ticket", required=True, type=Path)
    args = parser.parse_args()
    try:
        account = pwd.getpwnam("pentester")
        if os.geteuid() != account.pw_uid or os.getegid() != account.pw_gid or account.pw_uid == 0:
            authority._reject()
        envelope, _ = protected_record(args.ticket)
        runtime_authority, _ = protected_record(AUTHORITY_PATH)
        resource, resource_raw = protected_record(RESOURCE_PATH)
        ticket = validate_start_ticket(envelope, runtime_authority, resource, resource_raw)
        if args.ticket != Path("/run/lyrashield/tickets") / f"{ticket['requestId']}.json":
            authority._reject()
        os.chdir(ticket["command"]["cwd"])
        # All signature, source, identity and scope verification precedes this
        # admission point. The controller's separately armed execution watchdog
        # remains responsible after admission, including a stopped wrapper.
        admitted_at = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
        if (
            not nanoseconds(ticket["clock"]["issuedAtNs"])
            <= admitted_at
            < nanoseconds(ticket["clock"]["deadlineNs"])
        ):
            authority._reject()
        frame = {
            "schema": "lyrashield-sandbox-start-admission/1",
            "requestId": ticket["requestId"],
            "guardId": ticket["guardId"],
            "commandSha256": ticket["commandSha256"],
            "admittedAtNs": str(admitted_at),
            "executionDeadlineNs": ticket["executionDeadlineNs"],
        }
        os.write(2, ADMISSION_PREFIX + canonical(frame) + b"\n")
        os.execvp(ticket["command"]["argv"][0], ticket["command"]["argv"])  # noqa: S606  # nosec B606: starts the signed sandbox command after signature, identity, scope and deadline verification
    except (OSError, ValueError, authority.ControllerUnavailableError):
        sys.stderr.write("Sandbox start admission unavailable\n")
        return 125


if __name__ == "__main__":
    raise SystemExit(main())
