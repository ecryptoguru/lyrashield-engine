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
                            "PidMode": "",
                            "IpcMode": "private",
                            "UTSMode": "",
                            "UsernsMode": "",
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


def test_docker_calls_pin_local_socket_and_scrub_overrides(monkeypatch):
    calls = []
    monkeypatch.setenv("DOCKER_HOST", "tcp://remote:2375")
    monkeypatch.setenv("DOCKER_CONTEXT", "foreign")
    monkeypatch.setenv("DOCKER_TLS_VERIFY", "1")
    monkeypatch.setattr(probe, "local_endpoint", lambda: "/safe/docker.sock")
    monkeypatch.setattr(
        probe.subprocess, "run", lambda *args, **kwargs: calls.append((args, kwargs))
    )
    probe.invoke(["image", "inspect", probe.IMAGE])
    args, kwargs = calls[0]
    assert args[0][:3] == [probe.DOCKER, "--host", "unix:///safe/docker.sock"]
    assert not {"DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS_VERIFY"} & kwargs["env"].keys()


def test_non_socket_endpoint_rejected(monkeypatch):
    monkeypatch.setattr(probe, "local_endpoint", lambda: __file__)
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


@pytest.mark.parametrize("result", [(1, b""), (0, b"malformed"), (0, b"\xff")])
def test_unconfirmed_create_is_unresolved_and_identity_retained(monkeypatch, result):
    engine = Engine()
    identities = []

    def unconfirmed(args, **kwargs):
        if args[0] == "create":
            return subprocess.CompletedProcess(args, *result)
        return engine(args, **kwargs)

    monkeypatch.setattr(probe, "invoke", unconfirmed)
    monkeypatch.setattr(probe, "check_local_context", lambda: None)
    monkeypatch.setattr(probe, "persist_identity", lambda *values: identities.append(values))
    with pytest.raises(RuntimeError, match="outcome unresolved"):
        probe.run("receipt")
    assert len(identities) == 1


def test_host_pid_namespace_is_rejected_before_start(monkeypatch):
    engine = Engine()

    def host_pid(args, **kwargs):
        result = engine(args, **kwargs)
        if args[0] == "inspect" and result.returncode == 0:
            info = json.loads(result.stdout)
            info[0]["HostConfig"]["PidMode"] = "host"
            result.stdout = json.dumps(info).encode()
        return result

    monkeypatch.setattr(probe, "invoke", host_pid)
    monkeypatch.setattr(probe, "check_local_context", lambda: None)
    monkeypatch.setattr(probe, "persist_identity", lambda *_: None)
    with pytest.raises(RuntimeError, match="isolation"):
        probe.run("test-receipt")
    assert not any(call[0][0] == "start" for call in engine.calls)


def test_unconfirmed_create_preserves_unresolved_diagnosis_when_inspection_fails(monkeypatch):
    def unavailable(args, **_kwargs):
        if args[0] == "image":
            data = [{"Id": probe.IMAGE, "Os": "linux", "Architecture": "arm64", "Config": {}}]
            return subprocess.CompletedProcess(args, 0, json.dumps(data).encode())
        if args[0] == "create":
            raise subprocess.TimeoutExpired("docker create", 15)
        raise RuntimeError("daemon unavailable")

    monkeypatch.setattr(probe, "invoke", unavailable)
    monkeypatch.setattr(probe, "check_local_context", lambda: None)
    monkeypatch.setattr(probe, "persist_identity", lambda *_: None)
    with pytest.raises(RuntimeError, match="outcome unresolved"):
        probe.run("receipt")


@pytest.mark.parametrize("field", ["IpcMode", "UTSMode", "UsernsMode"])
def test_host_namespace_is_rejected_before_start(monkeypatch, field):
    engine = Engine()

    def host_namespace(args, **kwargs):
        result = engine(args, **kwargs)
        if args[0] == "inspect" and result.returncode == 0:
            info = json.loads(result.stdout)
            info[0]["HostConfig"][field] = "host"
            result.stdout = json.dumps(info).encode()
        return result

    monkeypatch.setattr(probe, "invoke", host_namespace)
    monkeypatch.setattr(probe, "check_local_context", lambda: None)
    monkeypatch.setattr(probe, "persist_identity", lambda *_: None)
    with pytest.raises(RuntimeError, match="isolation"):
        probe.run("test-receipt")
    assert not any(call[0][0] == "start" for call in engine.calls)
