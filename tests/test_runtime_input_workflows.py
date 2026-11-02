"""Keep pinned input hydration outside Docker and scoped to each image build."""

from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest
import yaml


ROOT = Path(__file__).parents[1]
HYDRATE = "Hydrate qualified runtime inputs"
COMMAND = "python3 containers/system-python-security/hydrate_runtime_inputs.py --download"
TOKEN = "${{ github.token }}"  # noqa: S105 - workflow expression, not a credential
WORKFLOWS = (
    ("ci.yml", "docker-smoke", "Build sandbox image"),
    ("publish-sandbox.yml", "publish", "Build and push an unqualified candidate"),
)


def load_workflow(filename: str) -> dict[str, Any]:
    return yaml.safe_load((ROOT / ".github/workflows" / filename).read_text())


def assert_hydration_contract(workflow: dict[str, Any], job_name: str, build_name: str) -> None:
    job = workflow["jobs"][job_name]
    steps = job["steps"]
    hydration = [step for step in steps if step.get("name") == HYDRATE]
    assert len(hydration) == 1
    hydrate = hydration[0]
    build_index = next(i for i, step in enumerate(steps) if step.get("name") == build_name)
    assert build_index > 0 and steps[build_index - 1] is hydrate
    build = steps[build_index]
    assert hydrate.get("if") == build.get("if")
    assert hydrate["run"] == COMMAND
    assert hydrate["env"] == {"GH_TOKEN": TOKEN}
    assert not hydrate.get("continue-on-error")
    assert [step for step in steps if "GH_TOKEN" in step.get("env", {})] == [hydrate]
    assert workflow["permissions"]["contents"] == "read"
    assert "permissions" not in job
    for scope in (workflow, job):
        assert "token" not in yaml.safe_dump(scope.get("env", {})).lower()
    # Local context plus credential-free checkout keep runner authentication out
    # of both BuildKit inputs and files copied into the build context.
    checkout = next(step for step in steps if step.get("uses", "").startswith("actions/checkout@"))
    assert checkout["with"]["persist-credentials"] is False
    if "uses" in build:
        assert build["with"]["context"] == "."
    assert "token" not in yaml.safe_dump(build).lower()
    assert not any(key.startswith("secret") for key in build.get("with", {}))


@pytest.mark.parametrize(("filename", "job_name", "build_name"), WORKFLOWS)
def test_runtime_input_hydration_precedes_each_image_build(
    filename: str, job_name: str, build_name: str
) -> None:
    workflow = load_workflow(filename)
    assert_hydration_contract(workflow, job_name, build_name)
    if filename == "ci.yml":
        assert workflow["permissions"] == {"contents": "read"}
        hydrate = next(s for s in workflow["jobs"][job_name]["steps"] if s.get("name") == HYDRATE)
        assert hydrate["if"] == "steps.changed_paths.outputs.docs_only != 'true'"
    else:
        assert workflow["permissions"] == {
            "contents": "read",
            "packages": "write",
            "id-token": "write",
            "attestations": "write",
            "artifact-metadata": "write",
        }


@pytest.mark.parametrize(
    "drift",
    (
        "missing",
        "after-build",
        "predicate",
        "global-token",
        "job-token",
        "build-token",
        "soft-failure",
    ),
)
def test_contract_rejects_hydration_and_credential_drift(drift: str) -> None:
    workflow = deepcopy(load_workflow("ci.yml"))
    steps = workflow["jobs"]["docker-smoke"]["steps"]
    hydrate = next(step for step in steps if step.get("name") == HYDRATE)
    build = next(step for step in steps if step.get("name") == "Build sandbox image")
    if drift == "missing":
        steps.remove(hydrate)
    elif drift == "after-build":
        steps.remove(hydrate)
        steps.insert(steps.index(build) + 1, hydrate)
    elif drift == "predicate":
        hydrate["if"] = "always()"
    elif drift == "global-token":
        workflow["env"] = {"GH_TOKEN": TOKEN}
    elif drift == "job-token":
        workflow["jobs"]["docker-smoke"]["env"] = {"GH_TOKEN": TOKEN}
    elif drift == "build-token":
        build.setdefault("with", {})["build-args"] = "GH_TOKEN=${{ github.token }}"
    elif drift == "soft-failure":
        hydrate["continue-on-error"] = True
    with pytest.raises(AssertionError):
        assert_hydration_contract(workflow, "docker-smoke", "Build sandbox image")


def assert_ci_cache_contract(workflow: dict[str, Any]) -> None:
    assert_hydration_contract(workflow, "docker-smoke", "Build sandbox image")
    steps = workflow["jobs"]["docker-smoke"]["steps"]
    build = next(step for step in steps if step.get("name") == "Build sandbox image")
    assert build.get("uses") == (
        "docker/build-push-action@c3c9e263c25d99ce0380d002d59b67737d91b0dc"
    )
    assert "run" not in build
    assert build["if"] == "steps.changed_paths.outputs.docs_only != 'true'"
    inputs = build["with"]
    assert inputs["context"] == "."
    assert inputs["file"] == "containers/Dockerfile"
    assert inputs["tags"] == "lyrashield-sandbox:ci"
    assert inputs["load"] is True
    assert inputs["push"] is False
    assert inputs["cache-from"] == "type=gha,version=2,scope=engine-sandbox-v1"
    assert inputs["cache-to"] == "type=gha,version=2,mode=max,scope=engine-sandbox-v1"
    assert not {"build-args", "build-contexts", "github-token"} & inputs.keys()
    assert not any(step.get("uses", "").startswith("docker/login-action@") for step in steps)
    assert workflow["permissions"] == {"contents": "read"}
    assert build["env"] == {"DOCKER_BUILD_RECORD_UPLOAD": "false"}


def test_ci_uses_authenticated_cache_action_and_loads_only_local_image() -> None:
    assert_ci_cache_contract(load_workflow("ci.yml"))


@pytest.mark.parametrize(
    ("key", "value"),
    (
        ("context", "{{defaultContext}}"),
        ("load", False),
        ("push", True),
        ("cache-from", "type=gha,version=2,scope=another-image"),
        ("cache-to", "type=gha,version=2,mode=min,scope=engine-sandbox-v1"),
        ("cache-to", "type=gha,version=2,mode=max,scope=engine-sandbox-v1,ignore-error=true"),
        ("build-args", "GH_TOKEN=${{ github.token }}"),
        ("secrets", "GIT_AUTH_TOKEN=${{ github.token }}"),
    ),
)
def test_ci_cache_contract_rejects_remote_context_push_and_cache_drift(
    key: str, value: str | bool
) -> None:
    workflow = deepcopy(load_workflow("ci.yml"))
    build = next(
        step
        for step in workflow["jobs"]["docker-smoke"]["steps"]
        if step.get("name") == "Build sandbox image"
    )
    build["with"][key] = value
    with pytest.raises(AssertionError):
        assert_ci_cache_contract(workflow)
