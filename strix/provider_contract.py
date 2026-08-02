# Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
"""Bounded, privacy-safe provider capability probes for deployment gates."""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from agents import function_tool
from agents.model_settings import ModelSettings
from agents.models.interface import ModelTracing
from agents.tool import ProgrammaticToolCallingTool

from strix.config.models import StrixProvider, configure_sdk_model_defaults


if TYPE_CHECKING:
    from strix.config.settings import Settings


_SAFE_ERROR_COMPONENT = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


@dataclass(frozen=True, slots=True)
class CapabilityResult:
    supported: bool
    error: str | None = None
    output_types: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "supported": self.supported,
            "error": self.error,
            "output_types": list(self.output_types),
        }


@dataclass(frozen=True, slots=True)
class ProviderContractResult:
    model: str
    baseline: CapabilityResult
    programmatic_tool_calling: CapabilityResult
    previous_response_id: CapabilityResult

    def as_dict(self) -> dict[str, Any]:
        return {
            "model": self.model,
            "baseline": self.baseline.as_dict(),
            "programmatic_tool_calling": self.programmatic_tool_calling.as_dict(),
            "previous_response_id": self.previous_response_id.as_dict(),
        }

    def meets_requirements(
        self,
        *,
        require_programmatic_tool_calling: bool,
        require_previous_response_id: bool,
    ) -> bool:
        return (
            self.baseline.supported
            and (not require_programmatic_tool_calling or self.programmatic_tool_calling.supported)
            and (not require_previous_response_id or self.previous_response_id.supported)
        )


@function_tool
def provider_contract_marker() -> str:
    """Return a fixed marker used only by the provider capability probe."""
    return "provider-contract-marker"


# The model must call this from generated code. A direct call proves only ordinary tools.
provider_contract_marker.allowed_callers = ["programmatic"]


def _safe_error(exc: BaseException) -> str:
    body = getattr(exc, "body", None)
    if isinstance(body, dict):
        for key in ("code", "type", "param"):
            value = body.get(key)
            if isinstance(value, str) and _SAFE_ERROR_COMPONENT.fullmatch(value):
                return f"{type(exc).__name__}.{value}"
    return type(exc).__name__


def _output_types(response: Any) -> tuple[str, ...]:
    output = getattr(response, "output", [])
    if not isinstance(output, list):
        return ()
    types: list[str] = []
    for item in output:
        value = item.get("type") if isinstance(item, dict) else getattr(item, "type", None)
        if isinstance(value, str):
            types.append(value)
    return tuple(types)


async def _request(
    model: Any,
    *,
    input_text: str,
    max_output_tokens: int,
    timeout_seconds: float,
    previous_response_id: str | None = None,
    tools: list[Any] | None = None,
) -> Any:
    return await asyncio.wait_for(
        model.get_response(
            system_instructions=(
                "You are a provider capability probe. Follow the user instruction exactly."
            ),
            input=input_text,
            model_settings=ModelSettings(max_tokens=max_output_tokens, store=True),
            tools=tools or [],
            output_schema=None,
            handoffs=[],
            tracing=ModelTracing.DISABLED,
            previous_response_id=previous_response_id,
            conversation_id=None,
            prompt=None,
        ),
        timeout=timeout_seconds,
    )


async def probe_provider_contract(
    settings: Settings,
    *,
    max_output_tokens: int = 64,
    timeout_seconds: float | None = None,
) -> ProviderContractResult:
    """Probe features using static text only; no target or scan content is sent."""
    model_name = (settings.llm.model or "").strip()
    if not model_name:
        raise RuntimeError("No LLM model configured for provider contract probe")
    if not 1 <= max_output_tokens <= 128:
        raise ValueError("max_output_tokens must be between 1 and 128")

    configure_sdk_model_defaults(settings)
    model = StrixProvider(settings=settings).get_model(model_name)
    timeout = timeout_seconds if timeout_seconds is not None else float(settings.llm.timeout)
    if timeout <= 0:
        raise ValueError("timeout_seconds must be greater than 0")

    try:
        baseline_response = await _request(
            model,
            input_text="Reply with exactly READY.",
            max_output_tokens=max_output_tokens,
            timeout_seconds=timeout,
        )
    except Exception as exc:  # noqa: BLE001 -- normalize untrusted provider failures
        unavailable = CapabilityResult(supported=False, error=_safe_error(exc))
        skipped = CapabilityResult(supported=False, error="baseline_unavailable")
        return ProviderContractResult(model_name, unavailable, skipped, skipped)

    baseline = CapabilityResult(supported=True, output_types=_output_types(baseline_response))

    try:
        programmatic_response = await _request(
            model,
            input_text=(
                "Use programmatic tool calling, not a direct function call, to invoke "
                "provider_contract_marker exactly once."
            ),
            max_output_tokens=max_output_tokens,
            timeout_seconds=timeout,
            tools=[provider_contract_marker, ProgrammaticToolCallingTool()],
        )
        programmatic_types = _output_types(programmatic_response)
        programmatic = CapabilityResult(
            "program" in programmatic_types,
            None if "program" in programmatic_types else "program_item_not_returned",
            programmatic_types,
        )
    except Exception as exc:  # noqa: BLE001 -- normalize untrusted provider failures
        programmatic = CapabilityResult(supported=False, error=_safe_error(exc))

    response_id = getattr(baseline_response, "response_id", None)
    if not isinstance(response_id, str) or not response_id:
        continuation = CapabilityResult(supported=False, error="baseline_response_id_missing")
    else:
        try:
            continuation_response = await _request(
                model,
                input_text="Reply with exactly CONTINUED.",
                max_output_tokens=max_output_tokens,
                timeout_seconds=timeout,
                previous_response_id=response_id,
            )
            continuation = CapabilityResult(
                supported=True,
                output_types=_output_types(continuation_response),
            )
        except Exception as exc:  # noqa: BLE001 -- normalize untrusted provider failures
            continuation = CapabilityResult(supported=False, error=_safe_error(exc))

    return ProviderContractResult(model_name, baseline, programmatic, continuation)
