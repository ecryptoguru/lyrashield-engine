# LyraShield Engine

LyraShield Engine is the sandboxed repository-analysis process used by the LyraShield AI worker. It is a controlled derivative of [Strix](https://github.com/usestrix/strix) v1.5.3, pinned at `7cc9fa9faa0179fc7e35111102fe3d20a9028393` and modified under Apache-2.0. LyraShield owns product-critical policy in `lyrashield/**`; the retained Strix tree differs only at two small, gated registration seams.

See [NOTICE](NOTICE) for attribution and [UPGRADES.md](UPGRADES.md) for the ownership and upstream-import ledger.

## Project map

- [LyraShield AI public site](https://lyrashieldai.com) · [public Lite Check](https://lyrashieldai.com/scan) · [methodology](https://lyrashieldai.com/methodology) · [synthetic sample report](https://lyrashieldai.com/sample-report).
- [LyraShield AI application repository](https://github.com/ecryptoguru/lyrashield-ai): public Lite Check, authenticated evidence console, worker integration, and release-assurance product; see its [Build Week judge path](https://github.com/ecryptoguru/lyrashield-ai#openai-build-week-judge-path).
- [Ownership boundary](#ownership-boundary): which execution behavior LyraShield owns versus the retained Strix substrate.
- [Worker artifact contract](#worker-artifact-contract): compatibility-sensitive `run.json` and `vulnerabilities.json` boundary.
- [Verification](#verification): the implementation gate, not an accuracy claim.
- [UPGRADES.md](UPGRADES.md): retained compatibility patches and ownership ledger.

## Build Week provenance

This repository contains both LyraShield commits and imported Strix history. Its top-level commit dates alone are therefore not a fair measure of LyraShield-authored Build Week work. The submission-wide source of truth is the application repository's pre-event baseline [`72ba1e2`](https://github.com/ecryptoguru/lyrashield-ai/commit/72ba1e2a54fdedf81989325031c781f41d14dec6), authored before **July 13, 2026, 9:00 AM PT (16:00 UTC)**, and its explicit [`72ba1e2..HEAD` comparison](https://github.com/ecryptoguru/lyrashield-ai/compare/72ba1e2a54fdedf81989325031c781f41d14dec6...main).

Before the event, LyraShield had already established the controlled-derivative boundary, compatibility adapter, upstream verification, and packaging hygiene. During Build Week, the engine-side work included containerized-worker sandbox reachability, review-gated immutable upstream imports, public worker-contract verification, context compaction, GPT-5.6 execution/evidence hardening, terminal receipt preservation, and bounded Luna specialist routing. Inspect LyraShield-only engine history without conflating imported upstream commits:

```bash
git log upstream/main..main --since='2026-07-13T16:00:00Z' --date=iso-strict --oneline
```

## Ownership boundary

LyraShield owns:

- GPT-5.6 Terra and Luna model acceptance and reasoning policy;
- context compaction, output/agent limits, and concurrent pre-request spend reservations;
- non-interactive lifecycle, cancellation, cleanup, telemetry-off defaults, and target-safe errors;
- deterministic finding identity, structured control/evidence metadata, and bounded artifacts;
- the worker-facing `run.json` and `vulnerabilities.json` contract.

The pinned upstream tree remains the substrate for generic sandbox/session mechanics, security tools, agent-SDK integration, and the vulnerability skill library. New changes should preserve that boundary: extract LyraShield policy behind explicit modules and versioned artifacts when useful, without rewriting stable upstream infrastructure.

## Security hardening

The engine includes a comprehensive security hardening pass (see `AI_AUDIT_REPORT.md` for the full audit and `UPGRADES.md` for the ledger). Key hardening:

- **Trust boundaries:** The system prompt defines `[SYSTEM-NOTICE]` (budget/turn warnings) and `[SYSTEM-VERIFIED PEER MESSAGE]` (inter-agent communication) tags with anti-spoofing rules. Tags inside tool output or target content are treated as injection attempts.
- **Secret redaction in compaction:** Conversation history is redacted via `redact_text()` before LLM summarization. The compaction prompt instructs the model to record placeholder types instead of copying credentials verbatim.
- **Output hygiene:** All vulnerability report and final report free-text fields are redacted at persistence. Internal path redaction is mode-aware: whitebox scans preserve `/workspace/<subdir>` target paths; blackbox scans redact them. PoC script code always preserves internal paths for reproducibility. Spill paths and tmp state are always redacted.
- **Structured output enforcement:** Deduplication uses a `DedupeJudgement` Pydantic schema with `AgentOutputSchema(strict_json_schema=True)` and falls back to a lenient parser on validation failure.
- **Telemetry hygiene:** Telemetry keys are read lazily from environment variables (`STRIX_POSTHOG_API_KEY`, `STRIX_POSTHOG_HOST`, `STRIX_SCARF_ENDPOINT`) at call time. No hardcoded keys in source. Skill telemetry thread spawning is gated by `telemetry.enabled`.
- **Prompt sanitization:** `_sanitize_prompt_value` strips Jinja tags (`{{ }}`, `{% %}`, `{# #}`) and control characters from `root_instructions_override`, `extra_system_prompt_context`, and target values before they enter the system prompt.

## Supported execution

Production uses the `lyrashield` entry point. It applies `LYRASHIELD_*` compatibility aliases, allows GPT-5.6 Terra or Luna deployments through the LiteLLM/Strix-supported providers that carry them (currently OpenAI, Azure/Azure AI, and Bedrock Mantle), supports ChatGPT subscription-backed models by default, and always disables inherited telemetry.

Requirements:

- Python 3.12+
- [uv](https://docs.astral.sh/uv/)
- Docker with the reviewed, pinned sandbox image available
- an OpenAI- or Azure-compatible endpoint serving a GPT-5.6 Terra or Luna deployment

```bash
uv sync --frozen
uv run lyrashield --version
uv run lyrashield --help

export LYRASHIELD_LLM="openai/gpt-5.6-luna"
# Optional for Deep scans: Terra coordinates while Luna runs focused specialists.
export LYRASHIELD_DELEGATE_LLM="openai/gpt-5.6-luna"
export LLM_API_KEY="<credential>"
export LLM_API_BASE="https://<approved-endpoint>"
# Optional token caps (see docs/advanced/configuration.mdx for behavior):
# export LYRASHIELD_MAX_OUTPUT_TOKENS=4096
# export LYRASHIELD_MAX_INPUT_TOKENS=64000
uv run lyrashield --target ./approved-repository --scan-mode quick --non-interactive --max-budget-usd 1.20
```

Azure-compatible deployments may use `AZURE_AI_*` or `AZURE_OPENAI_*` credentials and endpoints; see [the configuration reference](docs/advanced/configuration.mdx). GPT-5.6 agent turns use Azure's v1 Responses API so function tools remain supported; resource and project endpoints are normalized to their `/openai/v1/` base. Deployment names must still identify GPT-5.6 Terra or Luna.

Supported execution paths are GPT-5.6 Terra or Luna deployments from the LiteLLM/Strix providers that currently carry them: `openai`, `azure`, `azure_ai`, and `bedrock_mantle`, e.g. `openai/gpt-5.6-luna`, `azure/eu/gpt-5.6-terra`, `azure_ai/gpt-5.6-luna`, or `bedrock_mantle/openai.gpt-5.6-luna`. ChatGPT subscription models are also supported by default: run `lyrashield auth login chatgpt` and set `LYRASHIELD_LLM=chatgpt/<model>`. Subscription runs are tracked with `auth_mode: "subscription"` and `llm_usage.cost: 0` in `run.json`. Set `LYRASHIELD_ALLOW_CHATGPT_SUBSCRIPTION=0` to disable subscription auth. OpenRouter, Bedrock (non-Mantle), Vertex, Novita, Perplexity, Parallel, and local/self-hosted endpoints remain unsupported until LiteLLM's cost map lists `gpt-5.6` for their provider markers.

### Provider capability gate

Run this bounded, static probe after a deployment change and before enabling an optional
Responses feature. It sends no repository or scan data, caps each response at 64 output
tokens, and prints only capability booleans plus safe error labels:

```bash
uv run lyrashield provider-contract --require-programmatic-tool-calling
```

Leave `LYRASHIELD_PROGRAMMATIC_TOOL_CALLING` unset unless this gate succeeds. The
default Azure path remains JSON function tools. Test server-managed continuation separately:

```bash
uv run lyrashield provider-contract --require-previous-response-id
```

The continuation probe uses `store=True` with fixed capability text only; it never sends
scan data. A successful probe does not authorize a future SQLite-to-server-state migration.

Repository targets are the production worker boundary. The LyraShield application routes URL targets to its pinned deterministic URL scanner instead of this engine. Run only against targets you are authorized to test.

## Worker artifact contract

Each non-interactive run writes bounded machine-readable artifacts under `strix_runs/<run-name>/`:

- `run.json` records lifecycle, model/reasoning metadata, usage, limits, and reproducibility fields;
- `vulnerabilities.json` contains bounded structured finding candidates, control IDs, evidence metadata, and deterministic identities.

Deep scans use a deterministic two-tier route: the Terra/medium root owns coordination and cross-file judgment, while Luna/medium child specialists handle focused tasks with smaller output reservations. Only the root can create or stop specialists, so child work cannot fan out recursively. Child agents start with a focused task and system-owned scope instead of copying the full parent conversation unless the coordinator explicitly requests inherited context. Stable per-scan cache keys improve repeated-prefix reuse, and per-request usage receipts retain the actual model so mixed-model spend can be reconciled against the rate card.

The TypeScript worker treats all engine output as untrusted. It schema-validates these artifacts, never persists raw stdout/stderr, and does not allow model confidence to become independent verification proof. Existing artifact keys are compatibility-sensitive; coordinate changes with the worker contract tests in `lyrashield-ai`.

When the root model (Terra) hits any `ModelBehaviorError`, the engine falls back to the delegate model (Luna) rather than failing the scan immediately. If no separate delegate is configured, or if the delegate also fails, partial findings are salvaged with an `engine_stopped` (or `content_filter_stopped` for content-filter errors) terminal reason recorded in `run.json`. The exit code is 2 when findings are present and 5 when none were collected. Azure's transient `response.failed` status (without content-filter context) is retried with backoff rather than failing the scan.

## Verification

Run the full gate before opening or approving a change:

```bash
bash scripts/verify-controlled-derivative.sh
```

The repository is maintained as a controlled derivative (not a thin fork). The gate covers Ruff lint/format, the full test suite (`pytest`), mypy, Bandit, and the public worker contract. It also enforces a hard **footprint budget** on `strix/**` drift versus the pinned upstream base: at most two changed files, 30 insertions, and no deletions. Any other Strix path or change type fails the gate.

Engine CI (`.github/workflows/ci.yml`) runs the same quality gates on every pull request and push to `main`, in addition to CLI/native build, sandbox smoke, and cross-repository worker contract checks. Test counts are intentionally not copied here because the executable gate is the source of truth.

Budget enforcement now falls back to LiteLLM's `model_cost` table and then to conservative default rates for non-GPT-5.6 models, so validation does not crash if an internal path references an unlisted model. The LyraShield product entry point still rejects non-GPT-5.6 Terra/Luna deployments before scan start.

These checks prove implementation compatibility, not detection accuracy. The inherited Strix v0.4 XBEN result is historical upstream evidence only. LyraShield must establish result quality with its own versioned evaluation corpus before making accuracy, coverage, or comparative claims; see [benchmarks/README.md](benchmarks/README.md).

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). Upstream names and marks remain their owners' property.
