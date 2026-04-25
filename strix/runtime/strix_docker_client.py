"""StrixDockerSandboxClient — adds NET_ADMIN/NET_RAW capabilities + host-gateway.

The SDK's ``DockerSandboxClient._create_container`` does not expose a hook for
extending ``create_kwargs`` before ``containers.create`` is called. We subclass
and reimplement the method body verbatim from the SDK source, with two
additions before the final create call:

    create_kwargs.setdefault("cap_add", []).extend(["NET_ADMIN", "NET_RAW"])
    create_kwargs.setdefault("extra_hosts", {})["host.docker.internal"] = "host-gateway"

These are required for raw-socket pentest tools (nmap -sS) and for letting
the agent reach host-served apps via ``host.docker.internal``.

Pinned to ``openai-agents==0.14.6``. Bumping the SDK version requires
re-merging the parent body. Track upstream PR for an injection hook.

References:
    - PLAYBOOK.md §2.2
    - AUDIT.md §2.3 (C3 — original blocker)
    - SDK source: ``/tmp/openai-agents/src/agents/sandbox/sandboxes/docker.py:1434-1477``
"""

from __future__ import annotations

import uuid
from typing import Any

from agents.sandbox.manifest import Manifest
from agents.sandbox.sandboxes.docker import (
    DockerSandboxClient,
    _build_docker_volume_mounts,
    _docker_port_key,
    _manifest_requires_fuse,
    _manifest_requires_sys_admin,
)
from docker.models.containers import Container  # type: ignore[import-untyped, unused-ignore]
from docker.utils import parse_repository_tag  # type: ignore[import-untyped, unused-ignore]


class StrixDockerSandboxClient(DockerSandboxClient):
    """``DockerSandboxClient`` subclass that injects Strix-required capabilities.

    Only ``_create_container`` is overridden. All other behavior — image
    management, session lifecycle, port resolution, cleanup — is inherited.
    """

    async def _create_container(
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
            repo, tag = parse_repository_tag(image)
            self.docker_client.images.pull(repo, tag=tag or None, all_tags=False)

        assert self.image_exists(image)
        environment: dict[str, str] | None = None
        if manifest:
            environment = await manifest.environment.resolve()
        create_kwargs: dict[str, Any] = {
            "entrypoint": ["tail"],
            "image": image,
            "detach": True,
            "command": ["-f", "/dev/null"],
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
        cap_add = create_kwargs.setdefault("cap_add", [])
        if not isinstance(cap_add, list):  # defensive — parent always sets list
            cap_add = list(cap_add)
            create_kwargs["cap_add"] = cap_add
        for cap in ("NET_ADMIN", "NET_RAW"):
            if cap not in cap_add:
                cap_add.append(cap)

        extra_hosts = create_kwargs.setdefault("extra_hosts", {})
        extra_hosts["host.docker.internal"] = "host-gateway"

        return self.docker_client.containers.create(**create_kwargs)
