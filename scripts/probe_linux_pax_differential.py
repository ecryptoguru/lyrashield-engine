"""Optional, isolated Linux Go parser differential over synthetic bytes only.

No image download, archive extraction, xattr application or host bind mounts.
This is not an OCI runtime/overlay or capability-enforcement test.
"""

# ruff: noqa: INP001, T201
import base64
import hashlib
import io
import json
import subprocess
import tarfile
import uuid

from scripts.probe_pax_capability import inspect_layer


IMAGE = "sha256:8ac98ca534ac3f51e1f420a1dd2c15e74c75cfa0f23f3ad27eb5d7236c349a0c"
DOCKER = "/usr/local/bin/docker"
CONTEXT = "desktop-linux"
KEY = b"SCHILY.xattr.security.capability"
VALUE = b"\x00\xff\n=\x80binary\x00"
OWNER = "org.lyrashield.synthetic-pax-probe"


def record(value):
    body = KEY + b"=" + value + b"\n"
    size = len(body) + 2
    while len(str(size)) + 1 + len(body) != size:
        size = len(str(size)) + 1 + len(body)
    return str(size).encode() + b" " + body


def fixture(payload):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        header = tarfile.TarInfo("pax")
        header.type = tarfile.XHDTYPE
        header.size = len(payload)
        archive.addfile(header, io.BytesIO(payload))
        member = tarfile.TarInfo("synthetic")
        member.size = 1
        archive.addfile(member, io.BytesIO(b"x"))
    return output.getvalue()


def source():
    single = fixture(record(VALUE))
    duplicate = fixture(record(b"first") + record(b"second"))
    observations = inspect_layer(io.BytesIO(single), "sha256:" + hashlib.sha256(single).hexdigest())
    if len(observations) != 1 or observations[0].value != VALUE:
        raise ValueError("synthetic probe mismatch")
    try:
        inspect_layer(io.BytesIO(duplicate), "sha256:" + hashlib.sha256(duplicate).hexdigest())
    except ValueError:
        pass
    else:
        raise ValueError("synthetic duplicate accepted")
    a, b = (base64.b64encode(x).decode("ascii") for x in (single, duplicate))
    return f"""package main
import ("archive/tar"; "bytes"; "encoding/base64"; "fmt"; "io")
func check(input string, want []byte) bool {{
 data, e := base64.StdEncoding.DecodeString(input); if e != nil {{ return false }}
 r := tar.NewReader(bytes.NewReader(data)); h, e := r.Next(); if e != nil {{ return false }}
 if h.Name != "synthetic" || h.Typeflag != tar.TypeReg {{ return false }}
 if !bytes.Equal([]byte(h.PAXRecords["SCHILY.xattr.security.capability"]), want) {{ return false }}
 _, e = r.Next(); return e == io.EOF
}}
func main() {{
 if check("{a}", []byte{{0,255,10,61,128,98,105,110,97,114,121,0}}) &&
    check("{b}", []byte("second")) {{ fmt.Print("SYNTHETIC_MATCH")
 }} else {{ fmt.Print("SYNTHETIC_MISMATCH") }}
}}
""".encode()


def invoke(args, *, input_bytes=None, timeout=15):
    return subprocess.run(  # noqa: S603
        [DOCKER, "--context", CONTEXT, *args],
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=timeout,
        check=False,
    )


def inspect_owned(name, token):
    result = invoke(["inspect", "--type", "container", name])
    if result.returncode:
        listing = invoke(["ps", "--all", "--filter", f"name=^/{name}$", "--format", "{{.Names}}"])
        if listing.returncode or listing.stdout.strip():
            raise RuntimeError("container state unavailable")
        return None
    data = json.loads(result.stdout)
    if len(data) != 1 or data[0]["Config"].get("Labels", {}).get(OWNER) != token:
        raise RuntimeError("container ownership verification failed")
    return data[0]


def run():
    program = source()
    token = uuid.uuid4().hex
    name = "codex-pax-synthetic-" + token
    image = invoke(["image", "inspect", IMAGE])
    if image.returncode:
        raise RuntimeError("required cached image unavailable")
    metadata = json.loads(image.stdout)
    if (
        len(metadata) != 1
        or metadata[0]["Id"] != IMAGE
        or metadata[0]["Os"] != "linux"
        or metadata[0]["Architecture"] != "arm64"
        or metadata[0]["Config"].get("Volumes")
    ):
        raise RuntimeError("cached image identity or volumes mismatch")
    create = [
        "create",
        "--name",
        name,
        "--label",
        f"{OWNER}={token}",
        "--pull=never",
        "--interactive",
        "--network=none",
        "--read-only",
        "--user=65534:65534",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--pids-limit=128",
        "--memory=768m",
        "--cpus=0.5",
        "--tmpfs=/tmp:rw,nosuid,nodev,exec,size=268435456,mode=1777",
        "--workdir=/tmp",
        "--env=GOCACHE=/tmp/gocache",
        "--env=GOTMPDIR=/tmp",
        "--env=GO111MODULE=off",
        "--env=GOTOOLCHAIN=local",
        "--entrypoint=/bin/sh",
        IMAGE,
        "-c",
        "umask 077; cat > /tmp/main.go; exec /usr/local/go/bin/go run /tmp/main.go",
    ]
    try:
        created = invoke(create)
        if created.returncode:
            raise RuntimeError("container creation failed")
        info = inspect_owned(name, token)
        if info is None or info["Image"] != IMAGE:
            raise RuntimeError("container identity verification failed")
        host = info["HostConfig"]
        config = info["Config"]
        if (
            host["NetworkMode"] != "none"
            or not host["ReadonlyRootfs"]
            or host.get("Privileged")
            or host.get("Binds")
            or host.get("VolumesFrom")
            or host.get("Devices")
            or host.get("CapAdd")
            or host.get("PidsLimit") != 128
            or host.get("Memory") != 768 * 1024 * 1024
            or host.get("NanoCpus") != 500_000_000
            or host.get("Tmpfs") != {"/tmp": "rw,nosuid,nodev,exec,size=268435456,mode=1777"}  # noqa: S108
            or info.get("Mounts")
            or config["User"] != "65534:65534"
            or "ALL" not in host.get("CapDrop", [])
            or not any("no-new-privileges" in x for x in host.get("SecurityOpt", []))
        ):
            raise RuntimeError("container isolation verification failed")
        outcome = invoke(
            ["start", "--attach", "--interactive", name], input_bytes=program, timeout=90
        )
        if outcome.returncode or outcome.stdout != b"SYNTHETIC_MATCH":
            raise RuntimeError("synthetic Linux parser comparison failed")
        return "synthetic Linux Go parser observations matched"
    finally:
        info = inspect_owned(name, token)
        if info is not None:
            removed = invoke(["rm", "--force", name])
            if removed.returncode or inspect_owned(name, token) is not None:
                raise RuntimeError("task-owned container cleanup failed")


if __name__ == "__main__":
    print(run())
