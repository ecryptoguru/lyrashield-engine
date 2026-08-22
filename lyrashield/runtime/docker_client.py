# Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
"""StrixDockerSandboxClient — preserves the image's ENTRYPOINT and adds
NET_ADMIN/NET_RAW capabilities + an opt-in host gateway.

The SDK's ``DockerSandboxClient._create_container`` does not expose a hook for
extending ``create_kwargs`` before ``containers.create`` is called. We subclass
and reimplement the method body verbatim from the SDK source, with three
deltas:

1. Drop the SDK's ``entrypoint=["tail"]`` override; supply ``["tail", "-f",
   "/dev/null"]`` as ``command`` instead. This lets our image's
   ``docker-entrypoint.sh`` actually run — without it, ``caido-cli`` never
   starts inside the container and ``bootstrap_caido`` retries against a
   dead port.
2. Append NET_ADMIN/NET_RAW to ``cap_add`` (required by ``nmap -sS`` and
   other raw-socket tools) only when the operator has opted in by setting
   ``STRIX_SANDBOX_ENABLE_NETWORK_CAPABILITIES=1``. The legacy
   ``STRIX_SANDBOX_DISABLE_NETWORK_CAPABILITIES`` is still honored if the new
   variable is not set.
3. Optionally add ``host.docker.internal`` → host-gateway to ``extra_hosts``
   when ``STRIX_SANDBOX_ALLOW_HOST_GATEWAY`` is explicitly enabled.

Pinned to the OpenAI Agents SDK revision declared in ``pyproject.toml`` and
``uv.lock``. Bumping the SDK requires re-merging the parent body. Track
upstream for an injection hook.
"""

from __future__ import annotations

import contextlib
import inspect
import logging
import os
import uuid
from typing import Any, cast

from agents.sandbox.errors import ExposedPortUnavailableError
from agents.sandbox.manifest import Manifest
from agents.sandbox.sandboxes.docker import (  # pyright: ignore[reportPrivateImportUsage]
    DockerSandboxClient,
    DockerSandboxSession,
    _build_docker_volume_mounts,
    _docker_port_key,
    _manifest_requires_fuse,
    _manifest_requires_sys_admin,
)
from agents.sandbox.session.sandbox_session import SandboxSession
from agents.sandbox.types import ExposedPortEndpoint
from docker import errors as docker_errors  # pyright: ignore[reportMissingTypeStubs]
from docker.models.containers import Container  # pyright: ignore[reportMissingTypeStubs]
from docker.types import LogConfig  # pyright: ignore[reportMissingTypeStubs]
from docker.types import Mount as DockerSDKMount  # pyright: ignore[reportMissingTypeStubs]
from docker.utils import parse_repository_tag  # pyright: ignore[reportMissingTypeStubs]
from requests.exceptions import RequestException


logger = logging.getLogger(__name__)


_SANDBOX_NETWORK_ENV = "STRIX_DOCKER_SANDBOX_NETWORK"
_SANDBOX_HOST_GATEWAY_ENV = "STRIX_SANDBOX_ALLOW_HOST_GATEWAY"
_REQUIRED_CREATE_CONTAINER_PARAMETERS = frozenset(
    {"self", "image", "manifest", "exposed_ports", "session_id"},
)


def assert_sdk_docker_compatibility() -> None:
    """Fail before a scan if the private SDK hook we mirror has changed."""
    parameters = set(inspect.signature(DockerSandboxClient._create_container).parameters)
    if _REQUIRED_CREATE_CONTAINER_PARAMETERS.issubset(parameters):
        return
    raise RuntimeError(
        "unsupported OpenAI Agents SDK Docker adapter signature. "
        "Install the LyraShield Engine pinned dependency set before running a scan."
    )


def host_gateway_enabled() -> bool:
    return os.environ.get(_SANDBOX_HOST_GATEWAY_ENV, "").strip().lower() in {
        "1",
        "true",
        "yes",
    }


def network_capabilities_enabled() -> bool:
    """Return whether NET_ADMIN/NET_RAW should be added to the sandbox.

    Network capabilities are now opt-in via ``STRIX_SANDBOX_ENABLE_NETWORK_CAPABILITIES``.
    The legacy ``STRIX_SANDBOX_DISABLE_NETWORK_CAPABILITIES`` is still honored when the
    new variable is not set, so explicit existing overrides continue to work.
    """
    new = os.environ.get("STRIX_SANDBOX_ENABLE_NETWORK_CAPABILITIES", "").strip().lower()
    if new:
        return new in {"1", "true", "yes"}
    old = os.environ.get("STRIX_SANDBOX_DISABLE_NETWORK_CAPABILITIES", "").strip().lower()
    if old in {"1", "true", "yes"}:
        return False
    return old in {"0", "false", "no", "off"}


def _sandbox_network() -> str | None:
    value = os.environ.get(_SANDBOX_NETWORK_ENV, "").strip()
    return value or None


# Network modes that give the sandbox unrestricted egress (docker default
# bridge NATs anywhere, host shares the host stack). Admission fails when the
# container actually landed on one of these.
_DENIED_NETWORK_MODES = frozenset({"", "default", "bridge", "host", "slirp4netns"})


def _assert_sandbox_network_admission(container: Any, docker_client: Any) -> None:
    """Fail sandbox admission unless the container runs on the configured network.

    Deny-by-default egress is supplied by the worker/network setup through
    ``STRIX_DOCKER_SANDBOX_NETWORK``; this check binds admission to the
    immutable runtime fact — the network mode Docker actually attached and the
    Docker network object's ``Internal`` flag — not to an environment variable
    the agent could influence. Proxy environment variables are steering only
    and never count as enforcement.
    """
    configured = _sandbox_network()
    attrs = cast("dict[str, Any]", getattr(container, "attrs", {}) or {})
    mode = str(cast("dict[str, Any]", attrs.get("HostConfig", {})).get("NetworkMode", "") or "")
    if configured is None:
        raise RuntimeError(
            "sandbox admission failed: STRIX_DOCKER_SANDBOX_NETWORK is not set. "
            "Attach the sandbox to an explicitly configured deny-by-default "
            "network (e.g. docker network create + set the variable) before "
            "starting a scan; the docker default bridge is not admitted."
        )
    if configured in _DENIED_NETWORK_MODES:
        raise RuntimeError(
            f"sandbox admission failed: STRIX_DOCKER_SANDBOX_NETWORK={configured!r} "
            "is not a deny-by-default sandbox network."
        )
    if mode != configured:
        raise RuntimeError(
            f"sandbox admission failed: container network mode {mode!r} does not "
            f"match the configured sandbox network {configured!r}."
        )
    # Inspect the Docker network object: the name alone is not attestation.
    # The network must exist and have Internal=True (deny-by-default egress).
    try:
        network = docker_client.networks.get(configured)
    except docker_errors.NotFound:
        raise RuntimeError(
            f"sandbox admission failed: configured network {configured!r} "
            "not found. Create it with `docker network create --internal` "
            "before starting a scan."
        ) from None
    except (docker_errors.APIError, RequestException, OSError) as exc:
        raise RuntimeError(
            f"sandbox admission failed: network inspect for {configured!r} failed: {exc}"
        ) from exc
    net_attrs = cast("dict[str, Any]", getattr(network, "attrs", {}) or {})
    if not net_attrs.get("Internal", False):
        raise RuntimeError(
            f"sandbox admission failed: network {configured!r} is not internal. "
            "Recreate it with `docker network create --internal` to enforce "
            "deny-by-default egress."
        )
    # Verify actual container attachment: NetworkMode can claim the expected
    # network while NetworkSettings.Networks shows a different (or absent)
    # attachment. The container must be a member of the configured network.
    networks = cast(
        "dict[str, Any]",
        cast("dict[str, Any]", attrs.get("NetworkSettings", {})).get("Networks", {}) or {},
    )
    if configured not in networks:
        attached = ", ".join(sorted(networks.keys())) or "<none>"
        raise RuntimeError(
            f"sandbox admission failed: container is not attached to the "
            f"configured network {configured!r} (attached: {attached}). "
            "The container's NetworkMode matches but its actual endpoint "
            "attachment does not include the configured deny-by-default network."
        )


def _apply_sandbox_network(create_kwargs: dict[str, Any]) -> None:
    network = _sandbox_network()
    if network:
        create_kwargs["network"] = network
        create_kwargs.pop("ports", None)


_DEFAULT_SANDBOX_MEM_LIMIT = "2g"
_DEFAULT_SANDBOX_SHM_SIZE = "512m"
_DEFAULT_SANDBOX_CPUS_NANO = 2_000_000_000
_DEFAULT_SANDBOX_PIDS_LIMIT = 512
_SANDBOX_CAP_OPT_OUT = frozenset({"0", "off", "none", "unlimited"})


def _sandbox_cap_value(env_name: str, default: str) -> str | None:
    """Resolve a sandbox cap knob: explicit override > pinned default.

    Blank/unset applies the pinned default; an explicit opt-out token
    (``0``/``off``/``none``/``unlimited``) restores docker's unbounded
    default for that knob.
    """
    value = os.environ.get(env_name, "").strip()
    if not value:
        return default
    if value.lower() in _SANDBOX_CAP_OPT_OUT:
        return None
    return value


def _apply_resource_limits(create_kwargs: dict[str, Any]) -> None:
    """Apply cgroup resource caps. Defaults **on** (founder-pinned).

    An autonomous agent executes model-generated, attacker-influenced
    commands inside this container; a fork bomb or memory hog must not be
    able to exhaust the host and take down co-located scans. Defaults:
    ``mem_limit=2g``, ``shm_size=512m`` (Chromium/headless tools OOM on
    docker's 64m default), ``cpus=2``, ``pids_limit=512``.

    Set any ``STRIX_SANDBOX_*`` knob to ``0``/``off``/``none``/``unlimited``
    to opt that knob back out to docker's unbounded default; any other
    value overrides the default. An unparseable value falls back to the
    pinned default — never to unbounded.
    """
    mem_limit = _sandbox_cap_value("STRIX_SANDBOX_MEM_LIMIT", _DEFAULT_SANDBOX_MEM_LIMIT)
    if mem_limit:
        create_kwargs["mem_limit"] = mem_limit

    shm_size = _sandbox_cap_value("STRIX_SANDBOX_SHM_SIZE", _DEFAULT_SANDBOX_SHM_SIZE)
    if shm_size:
        create_kwargs["shm_size"] = shm_size

    cpus = _sandbox_cap_value(
        "STRIX_SANDBOX_CPUS", str(_DEFAULT_SANDBOX_CPUS_NANO // 1_000_000_000)
    )
    nano_cpus: int | None = None
    if cpus:
        with contextlib.suppress(ValueError, OverflowError):
            candidate = int(float(cpus) * 1_000_000_000)
            if 0 < candidate <= 2**63 - 1:
                nano_cpus = candidate
    if nano_cpus is None and cpus:
        # Unparseable or out-of-range override: fall back to the pinned default.
        nano_cpus = _DEFAULT_SANDBOX_CPUS_NANO
    if nano_cpus is not None:
        create_kwargs["nano_cpus"] = nano_cpus

    pids_limit = _sandbox_cap_value("STRIX_SANDBOX_PIDS_LIMIT", str(_DEFAULT_SANDBOX_PIDS_LIMIT))
    if pids_limit:
        try:
            parsed_pids = int(pids_limit)
        except ValueError:
            parsed_pids = _DEFAULT_SANDBOX_PIDS_LIMIT
        if parsed_pids <= 0:
            parsed_pids = _DEFAULT_SANDBOX_PIDS_LIMIT
        create_kwargs["pids_limit"] = parsed_pids

    logger.info(
        "sandbox caps: mem=%s shm=%s cpus=%s pids=%s",
        create_kwargs.get("mem_limit", "unbounded"),
        create_kwargs.get("shm_size", "default"),
        create_kwargs.get("nano_cpus", "unbounded"),
        create_kwargs.get("pids_limit", "unbounded"),
    )


def _apply_log_limits(create_kwargs: dict[str, Any]) -> None:
    """Bound the container's json-file log so a runaway process in the sandbox
    (e.g. a tool that busy-loops writing to stdout) cannot fill the host disk
    and take the Docker daemon down with it.

    Unlike the cgroup caps above, this defaults **on** — docker's own default
    is an unbounded json-file, which is unsafe for an autonomous agent that
    executes arbitrary commands. ``max-file`` rotation means the on-disk cap is
    ``max-size * max-file``. Set ``STRIX_SANDBOX_LOG_MAX_SIZE`` to ``0``/``off``
    to opt back out to docker's default."""
    max_size = os.environ.get("STRIX_SANDBOX_LOG_MAX_SIZE", "50m").strip()
    if max_size.lower() in ("0", "off", "none", "unlimited"):
        return
    max_file = os.environ.get("STRIX_SANDBOX_LOG_MAX_FILE", "3").strip() or "3"
    create_kwargs["log_config"] = LogConfig(
        type=LogConfig.types.JSON,
        config={"max-size": max_size, "max-file": max_file},
    )


def _apply_run_labels(create_kwargs: dict[str, Any]) -> None:
    run_id = os.getenv("STRIX_RUN_ID")
    if not run_id:
        return
    labels = create_kwargs.setdefault("labels", {})
    if not isinstance(labels, dict):
        return
    labels["strix-run-id"] = run_id
    run_type = os.getenv("STRIX_RUN_TYPE")
    if run_type:
        labels["strix-run-type"] = run_type


class StrixDockerSandboxSession(DockerSandboxSession):
    sandbox_network: str = ""

    async def _resolve_exposed_port(self, port: int) -> ExposedPortEndpoint:
        try:
            self._container.reload()
        except docker_errors.APIError as e:
            raise ExposedPortUnavailableError(
                port=port,
                exposed_ports=self.state.exposed_ports,
                reason="backend_unavailable",
                context={
                    "backend": "docker",
                    "detail": "container_reload_failed",
                    "network": self.sandbox_network,
                },
                cause=e,
            ) from e

        attrs = cast("dict[str, Any]", getattr(self._container, "attrs", {}) or {})
        network_settings = cast("dict[str, Any]", attrs.get("NetworkSettings", {}) or {})
        networks = cast("dict[str, Any]", network_settings.get("Networks", {}) or {})
        endpoint = cast("dict[str, Any]", networks.get(self.sandbox_network) or {})
        ip = endpoint.get("IPAddress") or endpoint.get("GlobalIPv6Address")
        if isinstance(ip, str) and ip:
            host = f"[{ip}]" if ":" in ip else ip
            return ExposedPortEndpoint(host=host, port=port, tls=False)

        # Custom-network lookup failed; the container may not have joined the
        # configured network, or ports were published to the host. Fall back to
        # the SDK's default host-port resolver before giving up.
        logger.debug(
            "Custom-network IP lookup failed for port %s on network %s; "
            "falling back to SDK default resolver",
            port,
            self.sandbox_network,
        )
        return await super()._resolve_exposed_port(port)


class StrixDockerSandboxClient(DockerSandboxClient):
    # Host directories to bind-mount into the container, set by the docker
    # backend before ``create()``. Each item is ``{source, target, read_only}``.
    strix_bind_mounts: list[dict[str, Any]]

    def _ensure_image_available(self, image: str) -> None:
        if not self.image_exists(image):
            raise docker_errors.DockerException(f"Docker image unavailable after pull: {image}")

    async def _create_container(  # noqa: PLR0912, PLR0915 - mirrors the pinned SDK container builder
        self,
        image: str,
        *,
        manifest: Manifest | None = None,
        exposed_ports: tuple[int, ...] = (),
        session_id: uuid.UUID | None = None,
    ) -> Container:
        # ----- BEGIN VERBATIM COPY of DockerSandboxClient._create_container -----
        # SDK ref: src/agents/sandbox/sandboxes/docker.py:1434-1477 (v0.14.6).
        if not self.image_exists(image):
            if os.environ.get("STRIX_IMAGE_DIGEST", "").strip():
                raise RuntimeError(
                    f"Sandbox image {image} is not present locally and "
                    "STRIX_IMAGE_DIGEST is set. Pre-pull the image with the verified digest "
                    "before starting the scan."
                )
            repo, tag = parse_repository_tag(image)
            self.docker_client.images.pull(repo, tag=tag or None, all_tags=False)

        self._ensure_image_available(image)
        environment: dict[str, str] | None = None
        if manifest:
            environment = await manifest.environment.resolve()
        # Strix delta from the SDK body: drop ``entrypoint`` override and
        # supply ``tail -f /dev/null`` as ``command`` so the image's
        # ENTRYPOINT (``docker-entrypoint.sh``) runs setup, then ``exec
        # "$@"`` becomes ``exec tail -f /dev/null`` for the keep-alive.
        # Without this, caido-cli + the in-container CA trust never get
        # initialized.
        create_kwargs: dict[str, Any] = {
            "image": image,
            "detach": True,
            "command": ["tail", "-f", "/dev/null"],
            "environment": environment,
        }
        if manifest is not None:
            docker_mounts = _build_docker_volume_mounts(
                manifest,
                session_id=session_id,
            )
            if docker_mounts:
                create_kwargs["mounts"] = docker_mounts
            if _manifest_requires_fuse(manifest):
                create_kwargs.update(
                    devices=["/dev/fuse"],
                    cap_add=["SYS_ADMIN"],
                    security_opt=["apparmor:unconfined"],
                )
            elif _manifest_requires_sys_admin(manifest):
                create_kwargs.update(
                    cap_add=["SYS_ADMIN"],
                    security_opt=["apparmor:unconfined"],
                )
        if exposed_ports:
            create_kwargs["ports"] = {
                _docker_port_key(port): ("127.0.0.1", None) for port in exposed_ports
            }
        # ----- END VERBATIM COPY -----

        # Strix injections — append, don't overwrite, so FUSE/SYS_ADMIN survives.
        cap_add_value: Any = create_kwargs.setdefault("cap_add", [])
        if isinstance(cap_add_value, (list, tuple)):
            cap_items: list[Any] | tuple[Any, ...] = cap_add_value
            cap_add = [str(c) for c in cap_items]
        elif cap_add_value:
            cap_add = [str(cap_add_value)]
        else:
            cap_add = []
        create_kwargs["cap_add"] = cap_add
        if network_capabilities_enabled():
            for cap in ("NET_ADMIN", "NET_RAW"):
                if cap not in cap_add:
                    cap_add.append(cap)
            logger.info("Network capabilities enabled for sandbox")
        else:
            logger.info(
                "Network capabilities disabled for sandbox "
                "(default; set STRIX_SANDBOX_ENABLE_NETWORK_CAPABILITIES=1 to enable)"
            )

        if host_gateway_enabled():
            extra_hosts = create_kwargs.setdefault("extra_hosts", {})
            extra_hosts["host.docker.internal"] = "host-gateway"

        _apply_sandbox_network(create_kwargs)
        _apply_resource_limits(create_kwargs)
        _apply_log_limits(create_kwargs)
        _apply_run_labels(create_kwargs)

        # Strix injection: host bind mounts (e.g. large repos passed via --mount)
        # that bypass the SDK's file-by-file LocalDir copy.
        bind_mounts = getattr(self, "strix_bind_mounts", ())
        if bind_mounts:
            mounts = create_kwargs.setdefault("mounts", [])
            for spec in bind_mounts:
                mounts.append(
                    DockerSDKMount(
                        target=spec["target"],
                        source=spec["source"],
                        type="bind",
                        read_only=spec.get("read_only", True),
                    )
                )

        logger.debug(
            "Creating sandbox container: image=%s caps=%s exposed_ports=%s",
            image,
            cap_add,
            list(exposed_ports),
        )
        container = self.docker_client.containers.create(**create_kwargs)
        try:
            # Admission check reads the created container's actual network
            # attachment; on failure remove the never-started container so a
            # rejected scan cannot leak one.
            _assert_sandbox_network_admission(container, self.docker_client)
        except Exception:
            with contextlib.suppress(docker_errors.APIError, RequestException, OSError):
                cast("Any", container).remove(force=True)
            raise
        logger.info(
            "Sandbox container created: id=%s image=%s",
            container.short_id if hasattr(container, "short_id") else "?",
            image,
        )
        return container

    async def create(self, **kwargs: Any) -> SandboxSession:
        session = await super().create(**kwargs)
        network = _sandbox_network()
        inner = getattr(session, "_inner")  # noqa: B009
        if network and isinstance(inner, DockerSandboxSession):
            inner.__class__ = StrixDockerSandboxSession
            cast("StrixDockerSandboxSession", inner).sandbox_network = network
        return session

    async def delete(self, session: SandboxSession) -> SandboxSession:
        inner = getattr(session, "_inner")  # noqa: B009
        container_id = getattr(getattr(inner, "state", None), "container_id", None)
        if container_id:
            # Best-effort kill: NotFound/APIError cover a gone or unhappy
            # container. RequestException covers a torn-down daemon socket —
            # containers.get() -> inspect_container raises requests'
            # ConnectionError, which is a sibling of docker.errors.APIError
            # under requests.RequestException (not a subclass), so it escapes
            # an APIError-only suppress and surfaces a full traceback even
            # though this teardown is meant to be best-effort.
            with contextlib.suppress(
                docker_errors.NotFound, docker_errors.APIError, RequestException
            ):
                cast("Any", self.docker_client.containers.get(container_id)).kill()
        try:
            return await super().delete(session)
        except (docker_errors.APIError, RequestException, OSError) as exc:
            logger.exception(
                "docker delete raised for container %s; it may need manual reaping",
                container_id,
            )
            raise RuntimeError(f"sandbox container deletion failed: {container_id}") from exc
