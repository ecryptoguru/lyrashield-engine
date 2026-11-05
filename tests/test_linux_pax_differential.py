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
            output = ("a" * 64).encode()
        elif args[0] == "inspect" and self.exists:
            label = "other" if self.foreign else self.token
            output = json.dumps(
                [
                    {
                        "Id": "a" * 64,
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
    monkeypatch.setattr(probe, "check_local_context", lambda: None)
    monkeypatch.setattr(probe, "persist_identity", lambda *_: None)
    assert probe.run("test-receipt") == "synthetic Linux Go parser observations matched"
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
    monkeypatch.setattr(probe, "check_local_context", lambda: None)
    monkeypatch.setattr(probe, "persist_identity", lambda *_: None)
    with pytest.raises((RuntimeError, subprocess.TimeoutExpired)):
        probe.run("test-receipt")
    assert not engine.exists


def test_foreign_container_is_never_removed(monkeypatch):
    engine = Engine(foreign=True)
    monkeypatch.setattr(probe, "invoke", engine)
    monkeypatch.setattr(probe, "check_local_context", lambda: None)
    monkeypatch.setattr(probe, "persist_identity", lambda *_: None)
    with pytest.raises(RuntimeError, match="ownership"):
        probe.run("test-receipt")
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
    monkeypatch.setattr(probe, "check_local_context", lambda: None)
    monkeypatch.setattr(probe, "persist_identity", lambda *_: None)
    with pytest.raises(RuntimeError, match="isolation"):
        probe.run("test-receipt")
    assert not engine.exists
    assert not any(call[0][0] == "start" for call in engine.calls)


def test_create_timeout_is_unresolved_even_when_name_is_initially_absent(monkeypatch):
    engine = Engine()
    identities = []

    def delayed_create(args, **kwargs):
        if args[0] == "create":
            raise subprocess.TimeoutExpired("docker create", 15)
        return engine(args, **kwargs)

    monkeypatch.setattr(probe, "invoke", delayed_create)
    monkeypatch.setattr(probe, "check_local_context", lambda: None)
    monkeypatch.setattr(probe, "persist_identity", lambda *values: identities.append(values))
    with pytest.raises(RuntimeError, match="outcome unresolved"):
        probe.run("receipt")
    assert len(identities) == 1
    assert identities[0][1] == "codex-pax-synthetic-" + identities[0][2]
    assert not any(call[0][0] == "rm" for call in engine.calls)


def test_start_and_cleanup_use_immutable_id(monkeypatch):
    engine = Engine()
    monkeypatch.setattr(probe, "invoke", engine)
    monkeypatch.setattr(probe, "check_local_context", lambda: None)
    monkeypatch.setattr(probe, "persist_identity", lambda *_: None)
    probe.run("test-receipt")
    assert all(call[0][-1] == "a" * 64 for call in engine.calls if call[0][0] in {"start", "rm"})


def test_false_no_new_privileges_rejected(monkeypatch):
    engine = Engine()

    def unsafe_info(args, **kwargs):
        result = engine(args, **kwargs)
        if args[0] == "inspect" and result.returncode == 0:
            info = json.loads(result.stdout)
            info[0]["HostConfig"]["SecurityOpt"] = ["no-new-privileges=false"]
            result.stdout = json.dumps(info).encode()
        return result

    monkeypatch.setattr(probe, "invoke", unsafe_info)
    monkeypatch.setattr(probe, "check_local_context", lambda: None)
    monkeypatch.setattr(probe, "persist_identity", lambda *_: None)
    with pytest.raises(RuntimeError, match="isolation"):
        probe.run("test-receipt")
    assert not any(call[0][0] == "start" for call in engine.calls)


def test_remote_context_rejected_before_container_creation(monkeypatch):
    def remote(args, **_kwargs):
        return subprocess.CompletedProcess(
            args, 0, json.dumps([{"Endpoints": {"docker": {"Host": "tcp://remote:2375"}}}]).encode()
        )

    monkeypatch.setattr(probe, "invoke", remote)
    with pytest.raises(RuntimeError, match="local socket"):
        probe.check_local_context()


def test_identity_is_persisted_before_creation(tmp_path, monkeypatch):
    monkeypatch.setattr(probe, "require_no_acl", lambda _fd: None)
    tmp_path.chmod(0o700)
    probe.persist_identity(tmp_path, "synthetic-container", "token")
    identity = json.loads((tmp_path / "container-identity.json").read_text())
    assert identity == {
        "containerName": "synthetic-container",
        "label": probe.OWNER,
        "token": "token",
    }
    with pytest.raises(FileExistsError):
        probe.persist_identity(tmp_path, "different", "token")
