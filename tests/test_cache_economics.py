from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from lyrashield.evals.cache_economics import analyze_cache_economics, main


FIXTURES = Path(__file__).parent / "fixtures" / "cache-economics"

REPORT_KEYS = {
    "requests",
    "input_tokens",
    "cached_input_tokens",
    "cache_write_input_tokens",
    "uncached_input_tokens",
    "output_tokens",
    "estimated_cost_usd",
    "complete",
    "errors",
    "scenarios",
}


def _load_fixture(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _entry(
    model: str | None,
    input_tokens: Any,
    output_tokens: Any,
    cached: Any = 0,
    cache_write: Any = 0,
) -> dict[str, Any]:
    details: dict[str, Any] = {"cached_tokens": cached}
    if cache_write:
        details["cache_write_tokens"] = cache_write
    entry: dict[str, Any] = {
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "total_tokens": input_tokens + output_tokens
        if isinstance(input_tokens, int) and isinstance(output_tokens, int)
        else 0,
        "input_tokens_details": details,
    }
    if model is not None:
        entry["model"] = model
    return entry


def test_mixed_model_cache_economics_reconciles() -> None:
    run = {
        "llm_usage": {
            "request_usage_entries": [
                {
                    "model": "azure/gpt-5.6-luna",
                    "input_tokens": 1_000_000,
                    "output_tokens": 10_000,
                    "input_tokens_details": {
                        "cached_tokens": 600_000,
                        "cache_write_tokens": 100_000,
                    },
                },
                {
                    "model": "azure/gpt-5.6-terra",
                    "input_tokens": 100_000,
                    "output_tokens": 1_000,
                    "input_tokens_details": {
                        "cached_tokens": 50_000,
                        "cache_write_tokens": 25_000,
                    },
                },
            ]
        }
    }

    report = analyze_cache_economics(run)

    assert report.requests == 2
    assert report.input_tokens == 1_100_000
    assert report.cached_input_tokens == 650_000
    assert report.cache_write_input_tokens == 125_000
    assert report.uncached_input_tokens == 325_000
    assert report.output_tokens == 11_000
    assert report.complete is True


def test_mixed_model_cost_is_priced_per_model() -> None:
    run = {
        "llm_usage": {
            "request_usage_entries": [
                {
                    "model": "azure/gpt-5.6-luna",
                    "input_tokens": 1_000_000,
                    "output_tokens": 10_000,
                    "input_tokens_details": {
                        "cached_tokens": 600_000,
                        "cache_write_tokens": 100_000,
                    },
                },
                {
                    "model": "azure/gpt-5.6-terra",
                    "input_tokens": 100_000,
                    "output_tokens": 1_000,
                    "input_tokens_details": {
                        "cached_tokens": 50_000,
                        "cache_write_tokens": 25_000,
                    },
                },
            ]
        }
    }

    report = analyze_cache_economics(run)

    # Luna input 1M > 272k -> long-context: 2x input, 1.5x output:
    # (300k*0.2 + 600k*0.02 + 100k*0.25)*2 + 10k*1.2*1.5 = 0.212
    # Terra standard tier: 25k*2 + 50k*0.2 + 25k*2.5 + 1k*12 = 0.1345
    assert report.estimated_cost_usd == 0.3465
    assert report.to_dict()["estimated_cost_usd"] == 0.3465


def test_long_context_entry_uses_tier_multipliers() -> None:
    run = {
        "llm_usage": {
            "request_usage_entries": [
                _entry("azure/gpt-5.6-luna", 300_000, 1_000),
            ]
        }
    }

    report = analyze_cache_economics(run)

    # input > 272k: 2x input, 1.5x output -> 300k*0.2*2 + 1k*1.2*1.5
    assert report.complete is True
    assert report.estimated_cost_usd == 0.1218


def test_missing_model_marks_report_incomplete() -> None:
    run = {"llm_usage": {"request_usage_entries": [_entry(None, 100, 10)]}}

    report = analyze_cache_economics(run)

    assert report.complete is False
    assert report.errors
    assert "model_missing" in report.errors[0]


def test_absent_request_entries_marks_report_incomplete() -> None:
    report = analyze_cache_economics({"llm_usage": {"requests": 5}})

    assert report.complete is False
    assert report.errors == ("request_usage_entries_missing",)


def test_empty_request_entries_marks_report_incomplete() -> None:
    report = analyze_cache_economics({"llm_usage": {"request_usage_entries": []}})

    assert report.complete is False
    assert "request_usage_entries_missing" in report.errors


def test_missing_llm_usage_marks_report_incomplete() -> None:
    report = analyze_cache_economics({})

    assert report.complete is False
    assert report.errors == ("llm_usage_missing",)
    assert report.estimated_cost_usd is None


@pytest.mark.parametrize(
    "counter",
    [-5, 1.5, "100", None, True],
)
def test_negative_or_non_integer_counters_mark_report_incomplete(counter: Any) -> None:
    run = {
        "llm_usage": {
            "request_usage_entries": [
                _entry("azure/gpt-5.6-luna", counter, 10),
            ]
        }
    }

    report = analyze_cache_economics(run)

    assert report.complete is False
    assert report.errors
    assert "counter_invalid" in report.errors[0]


def test_cache_tokens_exceeding_input_mark_report_incomplete() -> None:
    run = {
        "llm_usage": {
            "request_usage_entries": [
                _entry("azure/gpt-5.6-luna", 100, 10, cached=80, cache_write=30),
            ]
        }
    }

    report = analyze_cache_economics(run)

    assert report.complete is False
    assert report.errors
    assert "cache_exceeds_input" in report.errors[0]


def test_unknown_model_cannot_be_priced() -> None:
    run = {
        "llm_usage": {
            "request_usage_entries": [
                _entry("azure/gpt-4o", 100, 10),
            ]
        }
    }

    report = analyze_cache_economics(run)

    assert report.complete is False
    assert "model_unpriced" in report.errors[0]


def test_missing_input_details_mark_report_incomplete() -> None:
    entry = _entry("azure/gpt-5.6-luna", 100, 10)
    del entry["input_tokens_details"]

    report = analyze_cache_economics({"llm_usage": {"request_usage_entries": [entry]}})

    assert report.complete is False
    assert "input_details_missing" in report.errors[0]


def test_one_invalid_entry_marks_whole_report_incomplete() -> None:
    run = {
        "llm_usage": {
            "request_usage_entries": [
                _entry("azure/gpt-5.6-luna", 100, 10),
                _entry("azure/gpt-5.6-luna", 100, 10, cached=90, cache_write=20),
            ]
        }
    }

    report = analyze_cache_economics(run)

    assert report.complete is False
    assert len(report.errors) == 1
    # The valid entry is still bucketed and priced; the invalid one is not.
    assert report.input_tokens == 100


@pytest.mark.parametrize(
    (
        "fixture",
        "requests",
        "input_tokens",
        "cached",
        "cache_write",
        "uncached",
        "output",
        "cost",
    ),
    [
        ("quick.json", 85, 3_956_553, 2_933_969, 70_844, 951_740, 14_840, 0.284546),
        (
            "standard.json",
            201,
            9_013_066,
            6_779_195,
            240_683,
            1_993_188,
            37_851,
            0.639813,
        ),
        (
            "deep.json",
            839,
            37_231_985,
            27_376_636,
            3_976_087,
            5_879_262,
            123_289,
            2.969205,
        ),
    ],
)
def test_sanitized_fixture_baselines(
    fixture: str,
    requests: int,
    input_tokens: int,
    cached: int,
    cache_write: int,
    uncached: int,
    output: int,
    cost: float,
) -> None:
    report = analyze_cache_economics(_load_fixture(fixture))

    assert report.complete is True
    assert report.errors == ()
    assert report.requests == requests
    assert report.input_tokens == input_tokens
    assert report.cached_input_tokens == cached
    assert report.cache_write_input_tokens == cache_write
    assert report.uncached_input_tokens == uncached
    assert report.output_tokens == output
    assert report.estimated_cost_usd == cost


@pytest.mark.parametrize(
    ("fixture", "savings"),
    [
        ("quick.json", 0.026674),
        ("standard.json", 0.059439),
        ("deep.json", 0.281665),
    ],
)
def test_input_reduction_scenario_savings(
    fixture: str, savings: float, capsys: pytest.CaptureFixture[str]
) -> None:
    exit_code = main([str(FIXTURES / fixture), "--input-reduction", "0.10"])

    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    scenario = next(s for s in payload["scenarios"] if s["name"] == "input_reduction")
    assert scenario["kind"] == "hypothetical"
    assert scenario["estimated_savings_usd"] == savings
    assert set(payload) == REPORT_KEYS


def test_cache_conversion_scenario_is_hypothetical(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main([str(FIXTURES / "quick.json"), "--cache-conversion", "0.10"])

    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    scenario = next(s for s in payload["scenarios"] if s["name"] == "cache_conversion")
    assert scenario["kind"] == "hypothetical"
    # 10% of (uncached 951,740 + write 70,844) repriced from 0.2/0.25 to 0.02.
    assert scenario["estimated_savings_usd"] == 0.018761


def test_cli_exit_2_for_incomplete_input(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    bad_run = tmp_path / "run.json"
    bad_run.write_text(
        json.dumps(
            {
                "llm_usage": {
                    "request_usage_entries": [
                        _entry("azure/gpt-5.6-luna", -5, 10),
                    ]
                }
            }
        ),
        encoding="utf-8",
    )

    exit_code = main([str(bad_run)])

    assert exit_code == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["complete"] is False


def test_cli_exit_2_for_unreadable_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main([str(tmp_path / "missing.json")])

    assert exit_code == 2
    capsys.readouterr()


def test_cli_never_echoes_unknown_run_record_fields(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    run = _load_fixture("quick.json")
    run["prompt_text"] = "secret-prompt-content"
    run["llm_usage"]["target_path"] = "/Users/someone/repo"
    run_file = tmp_path / "run.json"
    run_file.write_text(json.dumps(run), encoding="utf-8")

    exit_code = main([str(run_file)])

    assert exit_code == 0
    out = capsys.readouterr().out
    assert "secret-prompt-content" not in out
    assert "prompt_text" not in out
    assert "target_path" not in out
    assert set(json.loads(out)) == REPORT_KEYS
