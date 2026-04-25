"""Strix runtime — pluggable sandbox lifecycle on top of the Agents SDK.

- :mod:`.backends` — registry mapping ``STRIX_RUNTIME_BACKEND`` values
  to async factories that bring up a ``(client, session)`` pair. Ships
  with ``"docker"`` out of the box; ``register_backend`` lets downstream
  users add Daytona / K8s / Modal / etc. without forking.
- :mod:`.session_manager` — ``create_or_reuse`` / ``cleanup`` keyed
  by scan id; bundles the SDK session with a ready Caido client.
- :mod:`.caido_bootstrap` — runtime-agnostic Caido auth dance via
  ``session.exec``.
- :class:`strix.runtime.docker_client.StrixDockerSandboxClient` —
  ``DockerSandboxClient`` subclass that injects ``NET_ADMIN`` /
  ``NET_RAW`` capabilities and ``host.docker.internal`` extra-hosts
  (used only by the Docker backend).
"""
