"""The CI gate trusts current SDK tool outputs, never assistant JSON text."""

from __future__ import annotations

import asyncio
import json
import sys
from importlib import import_module
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, Mock

import pytest
from agents import Agent, RunContextWrapper, Runner
from agents.items import ModelResponse, ToolCallItem, ToolCallOutputItem
from agents.models.interface import Model
from agents.result import RunResult
from agents.run import RunConfig
from agents.usage import Usage
from openai.types.responses import (
    ResponseFunctionToolCall,
    ResponseOutputMessage,
    ResponseOutputText,
)

from lyrashield.agents import factory
from lyrashield.artifacts import state as state_module
from lyrashield.artifacts.state import ReportState
from lyrashield.lifecycle.agents import AgentCoordinator
from lyrashield.policy.models import _completed_stream_event
from lyrashield.tools.finish.tool import _do_finish, finish_scan
from strix.tools.coverage.tools import _record_impl, hydrate_coverage_from_disk
from tests.test_runtime_budget_preprocessing import _stub_scan_environment


main_module = import_module("lyrashield.interface.main")
QUALIFIED = {
    "success": True,
    "scan_completed": True,
    "coverage_complete": True,
    "assessment_reasons": [],
}
ARGUMENTS = {
    "executive_summary": "Assessment finished.",
    "methodology": "Reviewed authorized inputs.",
    "technical_analysis": "Observed checks recorded.",
    "recommendations": "Follow up open work.",
}


def finish_run_result(output: Any, *, final_output: Any = None) -> RunResult:
    """A typed SDK boundary fixture; end-to-end tests below use the real Runner."""
    agent = Agent(name="root", tools=[finish_scan])
    call = ResponseFunctionToolCall(
        type="function_call",
        name="finish_scan",
        call_id="fixture-finish",
        arguments=json.dumps(ARGUMENTS),
        id="fixture-call",
    )
    output = json.dumps(output) if isinstance(output, dict) else output
    return RunResult(
        input="fixture",
        new_items=[
            ToolCallItem(agent=agent, raw_item=call),
            ToolCallOutputItem(
                agent=agent,
                raw_item={
                    "type": "function_call_output",
                    "call_id": "fixture-finish",
                    "output": output,
                },
                output=output,
            ),
        ],
        raw_responses=[],
        final_output=final_output,
        input_guardrail_results=[],
        output_guardrail_results=[],
        tool_input_guardrail_results=[],
        tool_output_guardrail_results=[],
        context_wrapper=RunContextWrapper(context={"agent_id": "root", "parent_id": None}),
        _last_agent=agent,
    )


class ScriptedFinishModel(Model):
    def __init__(self, *, call_finish: bool, ordinary_text: bool = False) -> None:
        self.call_finish = call_finish
        self.text = (
            "Ordinary assistant text cannot override owned finish evidence."
            if ordinary_text
            else json.dumps(QUALIFIED)
        )
        self.calls = 0

    async def get_response(self, *_args: Any, **_kwargs: Any) -> ModelResponse:
        self.calls += 1
        if self.call_finish and self.calls == 1:
            output = [
                ResponseFunctionToolCall(
                    type="function_call",
                    name="finish_scan",
                    call_id="finish-current",
                    arguments=json.dumps(ARGUMENTS),
                    id="call-current",
                )
            ]
        else:
            output = [
                ResponseOutputMessage(
                    id=f"message-{self.calls}",
                    type="message",
                    role="assistant",
                    status="completed",
                    content=[
                        ResponseOutputText(type="output_text", text=self.text, annotations=[])
                    ],
                )
            ]
        return ModelResponse(output=output, usage=Usage(), response_id=f"response-{self.calls}")

    async def stream_response(self, *args: Any, **kwargs: Any):
        yield _completed_stream_event(await self.get_response(*args, **kwargs), "offline-model")


@pytest.mark.parametrize("scenario", ["truncated_finish", "no_finish", "complete_then_text"])
@pytest.mark.parametrize("streamed", [False, True])
def test_actual_runner_assistant_json_never_qualifies_completion(
    tmp_path, monkeypatch, scenario, streamed
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("LYRASHIELD_RUN_RECORD_V1_1", "0")
    monkeypatch.setenv("STRIX_SANDBOX_MODE", "local")
    hydrate_coverage_from_disk(tmp_path)
    state = ReportState("sdk-provenance")
    monkeypatch.setattr(state_module, "get_global_report_state", lambda: state)
    configured = factory.load_settings()
    configured = configured.model_copy(
        update={"context": configured.context.model_copy(update={"tool_output_max_bytes": 1024})}
    )
    monkeypatch.setattr(factory, "load_settings", lambda: configured)
    model = ScriptedFinishModel(
        call_finish=scenario != "no_finish", ordinary_text=scenario == "complete_then_text"
    )

    async def run_script():
        coordinator = AgentCoordinator()
        await coordinator.register("root", "root", None)
        if scenario == "truncated_finish":
            for index in range(30):
                child = f"child-{index}"
                await coordinator.register(child, child, "root")
                await coordinator.set_status(child, "failed")
        else:
            _record_impl(
                surface="application",
                risk_area="baseline",
                outcome="no_issue_found",
                evidence="Assigned baseline assessed",
                agent_id="root",
                agent_name="root",
            )
        if scenario == "no_finish":
            # A real completed receipt from prior work cannot authenticate a
            # message-only finish decision in this SDK invocation.
            _do_finish(parent_id=None, agent_graph=await coordinator.snapshot(), **ARGUMENTS)
        registered = factory.build_strix_agent(is_root=True)
        agent = Agent(
            name="root",
            model=model,
            tools=registered.tools,
            tool_use_behavior=registered.tool_use_behavior
            if scenario != "complete_then_text"
            else "run_llm_again",
        )
        context = {"agent_id": "root", "parent_id": None, "coordinator": coordinator}
        config = RunConfig(tracing_disabled=True)
        if streamed:
            result = Runner.run_streamed(
                agent, "offline authorized fixture", context=context, run_config=config
            )
            async for _event in result.stream_events():
                pass
            return result
        return await Runner.run(
            agent, "offline authorized fixture", context=context, run_config=config
        )

    result = asyncio.run(run_script())
    assert (result.final_output, result.new_items[-1].type) == (model.text, "message_output_item")
    assert model.calls == (1 if scenario == "no_finish" else 2)
    if scenario == "truncated_finish":
        output = next(
            item.output for item in result.new_items if isinstance(item, ToolCallOutputItem)
        )
        assert "truncated" in output
    source = tmp_path / "source"
    source.mkdir()
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "lyrashield",
            "-t",
            str(source),
            "-n",
            "--scope-mode",
            "full",
            "--run-name",
            "sdk-provenance",
            "--fail-on",
            "high",
        ],
    )
    _stub_scan_environment(monkeypatch)
    monkeypatch.setattr(main_module, "_persist_run_record", Mock())
    monkeypatch.setattr(main_module, "pull_docker_image", Mock())
    monkeypatch.setattr(main_module, "get_global_report_state", lambda: state)
    monkeypatch.setattr(main_module, "run_cli", AsyncMock(return_value=result))
    if scenario == "complete_then_text":
        main_module.main()
    else:
        with pytest.raises(SystemExit) as exit_info:
            main_module.main()
        assert exit_info.value.code == 5
    assert main_module._non_interactive_exit_code(state) == 0
    hydrate_coverage_from_disk(tmp_path / "cleared")


@pytest.mark.parametrize(
    "corruption",
    [
        "message_only",
        "mismatched_call",
        "different_agent",
        "child_context",
        "unregistered",
        "raw_output_mismatch",
        "output_before_call",
        "duplicate_call_id",
        "latest_finish_invalid",
        "pending_finish",
    ],
)
def test_finish_tool_provenance_rejects_ambiguous_or_foreign_items(corruption) -> None:
    result = finish_run_result(QUALIFIED, final_output=json.dumps(QUALIFIED))
    root = result.last_agent
    call, output = result.new_items
    if corruption == "message_only":
        result.new_items = []
    elif corruption == "mismatched_call":
        output.raw_item["call_id"] = "unmatched"
    elif corruption == "different_agent":
        output.agent = Agent(name="different", tools=[finish_scan])
    elif corruption == "child_context":
        result.context_wrapper.context["parent_id"] = "parent"
    elif corruption == "unregistered":
        root.tools = []
    elif corruption == "raw_output_mismatch":
        output.raw_item["output"] = "different actual tool output"
    elif corruption == "output_before_call":
        result.new_items = [output, call]
    elif corruption == "duplicate_call_id":
        earlier = ToolCallItem(
            agent=root, raw_item=call.raw_item.model_copy(update={"name": "other_tool"})
        )
        prior_output = ToolCallOutputItem(
            agent=root, raw_item=dict(output.raw_item), output=output.output
        )
        # A last-name map must not relabel this earlier non-finish output.
        output.output = output.raw_item["output"] = "truncated finish output"
        result.new_items = [earlier, prior_output, call, output]
    elif corruption == "pending_finish":
        result.new_items.append(
            ToolCallItem(
                agent=root, raw_item=call.raw_item.model_copy(update={"call_id": "pending-finish"})
            )
        )
    else:
        later = ToolCallItem(
            agent=root, raw_item=call.raw_item.model_copy(update={"call_id": "later-finish"})
        )
        later_output = ToolCallOutputItem(
            agent=root,
            raw_item={
                "type": "function_call_output",
                "call_id": "later-finish",
                "output": "truncated finish output",
            },
            output="truncated finish output",
        )
        result.new_items.extend([later, later_output])
    state = SimpleNamespace(run_record={"status": "completed"}, vulnerability_reports=[])
    assert main_module._non_interactive_exit_code(state, fail_on="high", finish_result=result) == 5
