"""Auxiliary request admission bounds Unicode cost and settles usage first."""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any, cast

import pytest
from agents.model_settings import ModelSettings
from agents.usage import Usage
from openai.types.responses import ResponseOutputMessage, ResponseOutputText

from lyrashield.artifacts import dedupe
from lyrashield.artifacts import state as state_module
from lyrashield.artifacts.state import ReportState
from lyrashield.lifecycle import compaction
from lyrashield.lifecycle import hooks as hooks_module
from lyrashield.lifecycle.hooks import BudgetExceededError, ReportUsageHooks
from lyrashield.triage import service


if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path


@pytest.fixture(autouse=True)
def clear_token_estimate_cache() -> Iterator[None]:
    hooks_module._estimate_cache.clear()
    yield
    hooks_module._estimate_cache.clear()


def _response() -> SimpleNamespace:
    return SimpleNamespace(
        response_id=None,
        usage=Usage(requests=1, input_tokens=100, output_tokens=10, total_tokens=110),
        output=[
            ResponseOutputMessage(
                id="triage-message",
                type="message",
                role="assistant",
                status="completed",
                content=[
                    ResponseOutputText(
                        type="output_text",
                        annotations=[],
                        text=json.dumps(
                            {
                                "disposition": "NEEDS_REVIEW",
                                "confidence": 0.7,
                                "explanation": "Needs validation",
                            }
                        ),
                    )
                ],
            )
        ],
    )


@pytest.mark.parametrize("auxiliary", ["dedupe", "triage", "compaction"])
@pytest.mark.parametrize(
    "payload",
    [
        "ASCII evidence",
        "汉字日本語" * 40,
        "😀🚀" * 40,
        '{"query":"SELECT * FROM users WHERE id = 1"}',
        "def scan():\n    return input()\n",
    ],
    ids=["ascii", "cjk", "emoji", "json", "code"],
)
@pytest.mark.parametrize("missing_tokenizer", [False, True])
@pytest.mark.asyncio
async def test_auxiliary_reservation_covers_tokenized_wire_payload_and_overhead(
    monkeypatch: pytest.MonkeyPatch, auxiliary: str, payload: str, missing_tokenizer: bool
) -> None:
    def counter(**kwargs: Any) -> int:
        if missing_tokenizer:
            raise RuntimeError("tokenizer unavailable")
        return len(kwargs["text"].encode("utf-8"))

    monkeypatch.setattr("litellm.token_counter", counter)
    hooks_module._estimate_cache.clear()
    monkeypatch.setattr(state_module, "_global_report_state", None)
    hooks = ReportUsageHooks(model="openai/gpt-6-luna", max_budget_usd=1)
    monkeypatch.setattr(hooks_module, "_active_hooks", hooks)
    observed = 0.0
    conservative_cost = 0.0

    async def request(**kwargs: Any) -> SimpleNamespace:
        nonlocal observed, conservative_cost
        observed = sum(hooks._reservations.values())
        wire_bytes = len((kwargs["system_instructions"] or "").encode()) + len(
            kwargs["input"].encode()
        )
        output_cap = 512 if auxiliary == "dedupe" else 192
        conservative_cost = ((wire_bytes + 4096) * 0.125 + output_cap * 0.5) / 1_000_000
        return _response()

    model = SimpleNamespace(get_response=request)
    if auxiliary == "dedupe":
        await dedupe._request_dedupe_judgement(
            model=model,
            model_name="openai/gpt-6-luna",
            model_settings=ModelSettings(),
            user_msg=payload,
        )
    elif auxiliary == "compaction":
        await compaction._summarize(
            "openai/gpt-6-luna",
            payload,
            192,
            model_provider=cast("Any", SimpleNamespace(get_model=lambda _model: model)),
            settings=cast(
                "Any", SimpleNamespace(llm=SimpleNamespace(timeout=1, extra_headers=None))
            ),
        )
    else:
        await service._request_judgement(
            model=cast("Any", model),
            model_route="openai/gpt-6-luna",
            model_settings=ModelSettings(),
            prompt=payload,
            limits=service.TriageLimits(max_output_tokens=192),
        )
    assert observed >= conservative_cost > 0
    assert not hooks._reservations


@pytest.mark.parametrize("auxiliary", ["dedupe", "triage", "compaction"])
@pytest.mark.asyncio
async def test_unicode_auxiliary_request_is_rejected_before_exceeding_near_cap(
    monkeypatch: pytest.MonkeyPatch, auxiliary: str
) -> None:
    monkeypatch.setattr("litellm.token_counter", lambda **kwargs: len(kwargs["text"].encode()))
    hooks_module._estimate_cache.clear()
    monkeypatch.setattr(state_module, "_global_report_state", None)
    hooks = ReportUsageHooks(model="openai/gpt-6-luna", max_budget_usd=0.001)
    monkeypatch.setattr(hooks_module, "_active_hooks", hooks)
    requested = False

    async def request(**_kwargs: Any) -> SimpleNamespace:
        nonlocal requested
        requested = True
        return _response()

    model = SimpleNamespace(get_response=request)
    with pytest.raises(BudgetExceededError):
        if auxiliary == "dedupe":
            await dedupe._request_dedupe_judgement(
                model=model,
                model_name="openai/gpt-6-luna",
                model_settings=ModelSettings(),
                user_msg="😀" * 3000,
            )
        elif auxiliary == "compaction":
            await compaction._summarize(
                "openai/gpt-6-luna",
                "😀" * 3000,
                192,
                model_provider=cast("Any", SimpleNamespace(get_model=lambda _model: model)),
                settings=cast(
                    "Any", SimpleNamespace(llm=SimpleNamespace(timeout=1, extra_headers=None))
                ),
            )
        else:
            await service._request_judgement(
                model=cast("Any", model),
                model_route="openai/gpt-6-luna",
                model_settings=ModelSettings(),
                prompt="😀" * 3000,
                limits=service.TriageLimits(max_output_tokens=192),
            )
    assert requested is False
    assert not hooks._reservations


@pytest.mark.parametrize("auxiliary", ["dedupe", "compaction", "triage"])
@pytest.mark.asyncio
async def test_auxiliary_usage_is_durable_before_reservation_release_cancellation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, auxiliary: str
) -> None:
    state = ReportState(run_name="dedupe-settlement")
    state._run_dir = tmp_path
    monkeypatch.setattr(state_module, "_global_report_state", state)
    hooks = ReportUsageHooks(model="openai/gpt-6-luna", max_budget_usd=1)
    monkeypatch.setattr(hooks_module, "_active_hooks", hooks)
    release = hooks.release_out_of_band_request

    async def cancel_after_release(**kwargs: Any) -> None:
        await release(**kwargs)
        raise asyncio.CancelledError

    monkeypatch.setattr(hooks, "release_out_of_band_request", cancel_after_release)

    async def request(**_kwargs: Any) -> SimpleNamespace:
        return _response()

    with pytest.raises(asyncio.CancelledError):
        if auxiliary == "compaction":
            await compaction._summarize(
                "openai/gpt-6-luna",
                "compare",
                192,
                model_provider=cast(
                    "Any",
                    SimpleNamespace(get_model=lambda _model: SimpleNamespace(get_response=request)),
                ),
                settings=cast(
                    "Any", SimpleNamespace(llm=SimpleNamespace(timeout=1, extra_headers=None))
                ),
            )
        elif auxiliary == "triage":
            await service._request_judgement(
                model=cast("Any", SimpleNamespace(get_response=request)),
                model_route="openai/gpt-6-luna",
                model_settings=ModelSettings(),
                prompt="compare",
                limits=service.TriageLimits(max_output_tokens=192),
                on_response=lambda response: state.record_sdk_usage(
                    agent_id="triage",
                    agent_name="triage",
                    model="openai/gpt-6-luna",
                    usage=response.usage,
                    response_id=response.response_id,
                ),
            )
        else:
            await dedupe._request_dedupe_judgement(
                model=SimpleNamespace(get_response=request),
                model_name="openai/gpt-6-luna",
                model_settings=ModelSettings(),
                user_msg="compare",
            )
    receipt = json.loads((tmp_path / "run.json").read_text())["llm_usage"]
    assert receipt["requests"] == 1
    assert receipt["cost"] == 0.000015
    assert receipt["accounting_complete"] is False
    assert not hooks._reservations


@pytest.mark.parametrize("write_failure", ["false", "exception"])
@pytest.mark.asyncio
async def test_dedupe_keeps_estimated_spend_when_usage_receipt_write_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    write_failure: str,
) -> None:
    state = ReportState(run_name="dedupe-write-failure")
    state._run_dir = tmp_path
    if write_failure == "false":
        monkeypatch.setattr(state, "save_run_data", lambda **_kwargs: False)
    else:

        def fail_save(**_kwargs: Any) -> bool:
            raise OSError("receipt write failed")

        monkeypatch.setattr(state, "save_run_data", fail_save)

    monkeypatch.setattr(state_module, "_global_report_state", state)
    hooks = ReportUsageHooks(model="openai/gpt-6-luna", max_budget_usd=1)
    monkeypatch.setattr(hooks_module, "_active_hooks", hooks)
    reserve = hooks.reserve_out_of_band_request
    reservation: dict[str, Any] = {}

    async def capture_reservation(**kwargs: Any) -> None:
        reservation.update(kwargs)
        await reserve(**kwargs)

    monkeypatch.setattr(hooks, "reserve_out_of_band_request", capture_reservation)

    async def request(**_kwargs: Any) -> SimpleNamespace:
        return _response()

    await dedupe._request_dedupe_judgement(
        model=SimpleNamespace(get_response=request),
        model_name="openai/gpt-6-luna",
        model_settings=ModelSettings(),
        user_msg="compare",
    )

    key = reservation["key"]
    assert key not in hooks._reservations
    assert hooks._abandoned_floors[key] > 0
    assert hooks._committed_cost_floor == 0
