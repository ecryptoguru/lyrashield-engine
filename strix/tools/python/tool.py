"""``python_action`` — execute Python code in the sandbox with proxy helpers.

Stateless per-call. Each invocation:

1. Ships the shared :mod:`strix.tools.proxy._calls` module source into
   ``/tmp/`` inside the sandbox (single source of truth: the host-side
   ``proxy/tools.py`` and this kernel both import the same file). The
   logic is host-managed; updating the proxy helpers does not require
   an image rebuild.
2. Writes a per-call driver that connects a fresh ``caido_sdk_client``
   to the in-container Caido at ``localhost:48080``, defines user-facing
   wrappers (``list_requests``, ``view_request``, ``send_request``,
   ``repeat_request``, ``scope_rules``) bound to that client, then
   ``exec``s the user's code wrapped in an ``async def`` so top-level
   ``await`` works.
3. Captures ``stdout`` / ``stderr``, parses a sentinel-delimited JSON
   payload from the driver's output, and returns it as the tool result.

State is **not** preserved across calls. For multi-step workflows, write
a single combined script via ``apply_patch`` and run it with
``exec_command``, or pass intermediate results through files in
``/workspace/scratch/``.
"""

from __future__ import annotations

import base64
import importlib.resources
import io
import json
import logging
import uuid
from pathlib import Path
from typing import TYPE_CHECKING

from agents import RunContextWrapper, function_tool


if TYPE_CHECKING:
    from agents.sandbox.session.base_sandbox_session import BaseSandboxSession


logger = logging.getLogger(__name__)


_CALLS_SOURCE = (importlib.resources.files("strix.tools.proxy") / "_calls.py").read_text(
    encoding="utf-8"
)


_DRIVER_TEMPLATE = '''\
"""Auto-generated python_action driver. Do not edit."""

from __future__ import annotations

import asyncio
import base64
import io
import json
import sys
import textwrap
import traceback
import urllib.request

sys.path.insert(0, "/tmp")
import strix_calls  # noqa: E402  shipped alongside this driver

from caido_sdk_client import Client  # noqa: E402
from caido_sdk_client.types import TokenAuthOptions  # noqa: E402


_SENTINEL = "{sentinel}"
_USER_CODE_B64 = "{user_code_b64}"


def _login_as_guest() -> str:
    body = json.dumps(
        {{"query": "mutation {{ loginAsGuest {{ token {{ accessToken }} }} }}"}}
    ).encode("utf-8")
    req = urllib.request.Request(
        "http://127.0.0.1:48080/graphql",
        data=body,
        headers={{"Content-Type": "application/json"}},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
        payload = json.loads(resp.read())
    return str(payload["data"]["loginAsGuest"]["token"]["accessToken"])


async def _strix_main() -> None:
    client = Client("http://127.0.0.1:48080", auth=TokenAuthOptions(token=_login_as_guest()))
    await client.connect()

    async def list_requests(**kwargs):
        return await strix_calls.list_requests(client, **kwargs)

    async def view_request(request_id, *, part="request"):
        return await strix_calls.get_request(client, request_id, part=part)

    async def send_request(method, url, *, headers=None, body=""):
        connection, raw = strix_calls.build_raw_request(
            method=method, url=url, headers=headers or {{}}, body=body
        )
        return await strix_calls.replay_send_raw(client, raw=raw, connection=connection)

    async def repeat_request(request_id, *, modifications=None):
        mods = modifications or {{}}
        result = await strix_calls.get_request(client, request_id, part="request")
        if result is None or result.request.raw is None:
            raise ValueError(f"Request {{request_id}} not found")
        original = result.request
        raw_str = result.request.raw.decode("utf-8", errors="replace")
        components = strix_calls.parse_raw_request(raw_str)
        full_url = strix_calls.full_url_from_components(original, components, mods)
        modified = strix_calls.apply_modifications(components, mods, full_url)
        connection, raw = strix_calls.build_raw_request(
            method=modified["method"],
            url=modified["url"],
            headers=modified["headers"],
            body=modified["body"],
        )
        return await strix_calls.replay_send_raw(client, raw=raw, connection=connection)

    async def scope_rules(action, *, allowlist=None, denylist=None, scope_id=None, scope_name=None):
        if action == "list":
            return await strix_calls.scope_list(client)
        if action == "get":
            if not scope_id:
                raise ValueError("scope_id required for get")
            return await strix_calls.scope_get(client, scope_id)
        if action == "create":
            if not scope_name:
                raise ValueError("scope_name required for create")
            return await strix_calls.scope_create(
                client, name=scope_name, allowlist=allowlist, denylist=denylist
            )
        if action == "update":
            if not scope_id or not scope_name:
                raise ValueError("scope_id and scope_name required for update")
            return await strix_calls.scope_update(
                client, scope_id, name=scope_name, allowlist=allowlist, denylist=denylist
            )
        if action == "delete":
            if not scope_id:
                raise ValueError("scope_id required for delete")
            await strix_calls.scope_delete(client, scope_id)
            return {{"deleted": scope_id}}
        raise ValueError(f"Unknown action: {{action}}")

    user_code = base64.b64decode(_USER_CODE_B64).decode("utf-8")
    wrapped = "async def __strix_user():\\n    pass\\n" + textwrap.indent(user_code, "    ")

    namespace: dict = {{
        "list_requests": list_requests,
        "view_request": view_request,
        "send_request": send_request,
        "repeat_request": repeat_request,
        "scope_rules": scope_rules,
        "client": client,
    }}

    out_buf = io.StringIO()
    err_buf = io.StringIO()
    error: str | None = None

    real_stdout = sys.stdout
    real_stderr = sys.stderr
    sys.stdout = out_buf
    sys.stderr = err_buf
    try:
        try:
            exec(compile(wrapped, "<python_action>", "exec"), namespace)  # noqa: S102
            await namespace["__strix_user"]()
        except BaseException:
            error = traceback.format_exc()
    finally:
        sys.stdout = real_stdout
        sys.stderr = real_stderr

    payload = json.dumps(
        {{
            "stdout": out_buf.getvalue(),
            "stderr": err_buf.getvalue(),
            "error": error,
        }},
        ensure_ascii=False,
    )
    sys.stdout.write("\\n" + _SENTINEL + payload + "\\n")


asyncio.run(_strix_main())
'''


@function_tool(timeout=180)
async def python_action(
    ctx: RunContextWrapper,
    code: str,
    timeout: int = 60,
) -> str:
    """Execute Python code in the sandbox with Caido proxy helpers pre-bound.

    Each call is a fresh process — variables, imports, and function
    definitions do **not** persist between calls. For multi-step
    workflows, combine into a single ``code`` block, or write a script
    to ``/workspace/scratch/<name>.py`` via ``apply_patch`` and run with
    ``exec_command``.

    **Pre-bound proxy helpers** (no imports needed; all are async — use
    ``await``):

    - ``list_requests(httpql_filter=, first=, after=, sort_by=,
      sort_order=, scope_id=)`` → cursor-paginated SDK ``Connection``.
      Iterate ``connection.edges`` for entries.
    - ``view_request(request_id, part="request")`` → SDK request object
      with ``.request.raw`` / ``.response.raw`` bytes.
    - ``send_request(method, url, headers=None, body="")`` → dict with
      ``status``, ``response_raw``, ``elapsed_ms``.
    - ``repeat_request(request_id, modifications={"url"|"headers"|
      "body"|"params"|"cookies": ...})`` → same shape as
      ``send_request``.
    - ``scope_rules(action, allowlist=, denylist=, scope_id=,
      scope_name=)`` → SDK scope objects.

    Top-level ``await`` is supported — the body is wrapped in an async
    function. Use ``print()`` to emit visible output; the last
    expression is **not** auto-shown.

    Args:
        code: Python source to execute. Multi-line is fine.
        timeout: Hard timeout in seconds (default 60). The container
            is killed if the driver exceeds this.

    Returns:
        JSON dict with ``success``, ``stdout``, ``stderr``, ``error``
        (a formatted traceback if the user code raised).
    """
    inner = ctx.context if isinstance(ctx.context, dict) else {}
    session: BaseSandboxSession | None = inner.get("sandbox_session")
    if session is None:
        return json.dumps(
            {"success": False, "error": "No sandbox session in run context"},
            ensure_ascii=False,
        )

    sentinel = "__STRIX_PY_RESULT_" + uuid.uuid4().hex + "__"
    user_code_b64 = base64.b64encode(code.encode("utf-8")).decode("ascii")
    driver = _DRIVER_TEMPLATE.format(sentinel=sentinel, user_code_b64=user_code_b64)
    logger.info("python_action: invoking driver (code_len=%d, timeout=%ds)", len(code), timeout)
    # /tmp inside the sandbox container is single-user (pentester) and
    # disposable per scan; the multi-user race B108/S108 warns about
    # doesn't apply.
    driver_path = Path(f"/tmp/strix_driver_{uuid.uuid4().hex}.py")  # nosec B108
    calls_path = Path("/tmp/strix_calls.py")  # nosec B108

    try:
        await session.write(calls_path, io.BytesIO(_CALLS_SOURCE.encode("utf-8")))
        await session.write(driver_path, io.BytesIO(driver.encode("utf-8")))
        result = await session.exec("python3", "-u", str(driver_path), timeout=timeout)
    except Exception as exc:  # noqa: BLE001
        return json.dumps(
            {"success": False, "error": f"python_action launch failed: {exc}"},
            ensure_ascii=False,
        )
    finally:
        # Best-effort cleanup; ignore failure (the file is in /tmp anyway).
        try:
            await session.exec("rm", "-f", str(driver_path), timeout=5)
        except Exception:  # noqa: BLE001
            logger.debug("cleanup failed for %s", driver_path)

    raw_stdout = result.stdout.decode("utf-8", errors="replace")
    raw_stderr = result.stderr.decode("utf-8", errors="replace")

    if sentinel in raw_stdout:
        head, _, tail = raw_stdout.rpartition(sentinel)
        try:
            payload = json.loads(tail.strip())
        except json.JSONDecodeError as exc:
            return json.dumps(
                {
                    "success": False,
                    "error": f"Driver output not parseable: {exc}",
                    "stdout": raw_stdout,
                    "stderr": raw_stderr,
                },
                ensure_ascii=False,
            )
        return json.dumps(
            {
                "success": payload.get("error") is None,
                "stdout": (head.rstrip() + payload.get("stdout", "")) or "",
                "stderr": payload.get("stderr", "") or raw_stderr,
                "error": payload.get("error"),
            },
            ensure_ascii=False,
        )

    return json.dumps(
        {
            "success": False,
            "error": "Driver exited without producing a result sentinel",
            "stdout": raw_stdout,
            "stderr": raw_stderr,
        },
        ensure_ascii=False,
    )
