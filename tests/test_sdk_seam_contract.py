"""Contract test for the vendored agent SDK's public seams.

The engine pins the SDK by version range (see pyproject/UPGRADES: the former
git-SHA pin was a pre-release of the 0.19 line), so a lock refresh can move it.
Most seams are exercised by the full suite, but imports can succeed while a
*symbol* quietly disappears from a module the engine reaches for lazily, and a
signature can drift without any test failing until a scan is live. This file
pins, in one place:

1. Every ``agents.*`` name the product imports (inventoried dynamically from
   the source tree at test time, so new imports are covered automatically).
2. The private Docker adapter seam mirrored by ``assert_sdk_docker_compatibility``.
3. The usage-serialization shape the billing ledger depends on.
"""

from __future__ import annotations

import ast
import importlib
import inspect
from pathlib import Path

import pytest
from agents.sandbox.sandboxes.docker import DockerSandboxClient
from agents.usage import Usage, deserialize_usage, serialize_usage

from lyrashield.runtime import docker_client


PRODUCT_ROOTS = [
    Path(__file__).resolve().parent.parent / "lyrashield",
    Path(__file__).resolve().parent.parent / "lyrashield_adapter",
]


def _inventory_agent_imports() -> list[tuple[str, str]]:
    """Collect (module, imported_name) pairs for every agents.* import."""
    seams: set[tuple[str, str]] = set()
    for root in PRODUCT_ROOTS:
        for path in root.rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if (
                    isinstance(node, ast.ImportFrom)
                    and node.module
                    and node.module.startswith(("agents",))
                ):
                    for alias in node.names:
                        seams.add((node.module, alias.name))
    return sorted(seams)


def test_product_agent_imports_resolve() -> None:
    """Every agents.* symbol the product imports exists in the pinned SDK."""
    seams = _inventory_agent_imports()
    # Guard against the inventory silently going empty (e.g. a tree rename).
    assert len(seams) >= 20, f"import inventory unexpectedly small: {seams}"
    missing = []
    for module_name, symbol in seams:
        module = importlib.import_module(module_name)
        if not hasattr(module, symbol):
            missing.append(f"{module_name}.{symbol}")
    assert not missing, (
        "The pinned agent SDK no longer exports names the product imports: "
        f"{missing}. The SDK version moved under the engine — re-pin or adapt "
        "(see UPGRADES.md re-review cadence)."
    )


def test_docker_sandbox_create_container_seam() -> None:
    """The private Docker adapter hook the engine mirrors must keep its shape."""
    parameters = set(inspect.signature(DockerSandboxClient._create_container).parameters)
    assert {"self", "image", "manifest", "exposed_ports", "session_id"} <= parameters


def test_usage_serialization_seam() -> None:
    """The billing ledger round-trips SDK Usage objects via these functions."""
    usage = Usage(
        requests=1,
        input_tokens=10,
        output_tokens=2,
        total_tokens=12,
    )
    record = serialize_usage(usage)
    assert isinstance(record, dict)
    restored = deserialize_usage(record)
    assert restored.requests == 1
    assert restored.input_tokens == 10
    assert restored.output_tokens == 2


def test_tool_and_run_result_seams() -> None:
    """Names imported lazily on scan paths only — assert they exist explicitly."""
    # The runtime compatibility assertion is the same check the worker relies
    # on at scan time; it must never rot.
    docker_client.assert_sdk_docker_compatibility()


@pytest.mark.parametrize(
    ("module_name", "symbol"),
    [
        ("agents.run", "Runner"),
        ("agents.lifecycle", "RunHooks"),
        ("agents.memory", "Session"),
        ("agents.items", "ModelResponse"),
        ("agents.items", "TResponseInputItem"),
        ("agents.result", "RunResultBase"),
        ("agents.model_settings", "ModelSettings"),
        ("agents.agent_output", "AgentOutputSchemaBase"),
        ("agents.handoffs", "Handoff"),
        ("agents.sandbox.manifest", "Manifest"),
        ("agents.sandbox.session", "BaseSandboxSession"),
    ],
)
def test_core_runtime_seams(module_name: str, symbol: str) -> None:
    module = importlib.import_module(module_name)
    assert hasattr(module, symbol), f"{module_name}.{symbol} vanished from the SDK"
