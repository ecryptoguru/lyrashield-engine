"""Safety contracts for the optional Linux synthetic parser differential."""

import json
import subprocess

import pytest

from scripts import probe_linux_pax_differential as probe


class Engine:
    def __init__(self, *, run_out=b"SYNTHETIC_MATCH", foreign=False):
        self.calls = []
        self.exists = False
        self.run_out = run_out
        self.foreign = foreign
        self.token = None

    def __call__(self, args, *, input_bytes=None, timeout=15):
        self.calls.append((args, input_bytes, timeout))
        status = 0
        output = b""
        if args[:2] == ["image", "inspect"]:
            output = json.dumps(
                [{"Id": probe.IMAGE, "Os": "linux", "Architecture": "arm64", "Config": {}}]
            ).encode()
        elif args[0] == "create":
            self.token = next(x.split("=", 1)[1] for x in args if x.startswith(probe.OWNER + "="))
            self.exists = True
        elif args[0] == "inspect" and self.exists:
            label = "other" if self.foreign else self.token
            output = json.dumps(
                [
                    {
                        "Image": probe.IMAGE,
                        "Config": {"Labels": {probe.OWNER: label}, "User": "65534:65534"},
                        "HostConfig": {
                            "NetworkMode": "none",
                            "ReadonlyRootfs": True,
                            "Privileged": False,
                            "Binds": None,
                            "PidsLimit": 128,
                            "Memory": 768 * 1024 * 1024,
                            "NanoCpus": 500_000_000,
                            "Tmpfs": {"/tmp": "rw,nosuid,nodev,exec,size=268435456,mode=1777"},  # noqa: S108
                            "CapDrop": ["ALL"],
                            "SecurityOpt": ["no-new-privileges"],
                        },
                        "Mounts": [],
                    }
                ]
            ).encode()
        elif args[0] == "inspect":
            status = 1
        elif args[0] == "ps":
            output = b""
        elif args[0] == "start":
            if isinstance(self.run_out, Exception):
                raise self.run_out
            output = self.run_out
        elif args[0] == "rm":
            self.exists = False
        else:
            raise AssertionError(args)
        return subprocess.CompletedProcess(args, status, output)


def test_success_uses_isolation_and_removes_only_owned_container(monkeypatch):
    engine = Engine()
    monkeypatch.setattr(probe, "invoke", engine)
    assert probe.run() == "synthetic Linux Go parser observations matched"
    create = next(call[0] for call in engine.calls if call[0][0] == "create")
    for flag in (
        "--pull=never",
        "--network=none",
        "--read-only",
        "--user=65534:65534",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
    ):
        assert flag in create
    assert not any(flag in create for flag in ("--privileged", "--volume", "--mount"))
    assert not engine.exists
    assert any(call[0][0] == "rm" for call in engine.calls)


@pytest.mark.parametrize("result", [b"SYNTHETIC_MISMATCH", subprocess.TimeoutExpired("docker", 90)])
def test_failure_or_timeout_removes_owned_container(monkeypatch, result):
    engine = Engine(run_out=result)
    monkeypatch.setattr(probe, "invoke", engine)
    with pytest.raises((RuntimeError, subprocess.TimeoutExpired)):
        probe.run()
    assert not engine.exists


def test_foreign_container_is_never_removed(monkeypatch):
    engine = Engine(foreign=True)
    monkeypatch.setattr(probe, "invoke", engine)
    with pytest.raises(RuntimeError, match="ownership"):
        probe.run()
    assert engine.exists
    assert not any(call[0][0] == "rm" for call in engine.calls)


def test_rejects_unexpected_isolation_before_start_and_cleans_owned_container(monkeypatch):
    engine = Engine()

    def unsafe_info(args, **kwargs):
        result = engine(args, **kwargs)
        if args[0] == "inspect" and result.returncode == 0:
            info = json.loads(result.stdout)
            info[0]["HostConfig"]["NetworkMode"] = "bridge"
            result.stdout = json.dumps(info).encode()
        return result

    monkeypatch.setattr(probe, "invoke", unsafe_info)
    with pytest.raises(RuntimeError, match="isolation"):
        probe.run()
    assert not engine.exists
    assert not any(call[0][0] == "start" for call in engine.calls)
