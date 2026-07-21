# LyraShield Engine

LyraShield Engine is the sandboxed repository-analysis process used by the LyraShield AI worker. It is a controlled derivative of [Strix](https://github.com/usestrix/strix) v1.1.0, pinned at `7d5a67d234bd3faef34d22be8c6f5a9607de41a3` and modified under Apache-2.0. It is not a thin wrapper: LyraShield intentionally owns product-critical policy inside the derivative while retaining reviewed upstream sandbox, tool, and agent-SDK plumbing.

See [NOTICE](NOTICE) for attribution and [UPGRADES.md](UPGRADES.md) for the ownership and upstream-import ledger.

## Ownership boundary

LyraShield owns:

- GPT-5.6 Sol, Terra, and Luna model acceptance and reasoning policy;
- context compaction, output/agent limits, and concurrent pre-request spend reservations;
- non-interactive lifecycle, cancellation, cleanup, telemetry-off defaults, and target-safe errors;
- deterministic finding identity, structured control/evidence metadata, and bounded artifacts;
- the worker-facing `run.json` and `vulnerabilities.json` contract.

The pinned upstream tree remains the substrate for generic sandbox/session mechanics, security tools, agent-SDK integration, and the vulnerability skill library. New changes should preserve that boundary: extract LyraShield policy behind explicit modules and versioned artifacts when useful, without rewriting stable upstream infrastructure.

## Supported execution

Production uses the `lyrashield` entry point. It applies `LYRASHIELD_*` compatibility aliases and always disables inherited telemetry.

Requirements:

- Python 3.12+
- [uv](https://docs.astral.sh/uv/)
- Docker with the reviewed, pinned sandbox image available
- an OpenAI- or Azure-compatible endpoint serving a GPT-5.6 Sol, Terra, or Luna deployment

```bash
uv sync --frozen
uv run lyrashield --version
uv run lyrashield --help

export LYRASHIELD_LLM="openai/gpt-5.6-luna"
# Optional for Deep scans: Terra coordinates while Luna runs focused specialists.
export LYRASHIELD_DELEGATE_LLM="openai/gpt-5.6-luna"
export LLM_API_KEY="<credential>"
export LLM_API_BASE="https://<approved-endpoint>"
uv run lyrashield --target ./approved-repository --scan-mode quick --non-interactive --max-budget-usd 1.20
```

Azure-compatible deployments may use `AZURE_AI_*` or `AZURE_OPENAI_*` credentials and endpoints; see [the configuration reference](docs/advanced/configuration.mdx). GPT-5.6 agent turns use Azure's v1 Responses API so function tools remain supported; resource and project endpoints are normalized to their `/openai/v1/` base. Deployment names must still identify GPT-5.6 Sol, Terra, or Luna. Anthropic, Bedrock, Vertex, OpenRouter, local models, Perplexity, and Parallel are not supported execution paths.

Repository targets are the production worker boundary. The LyraShield application routes URL targets to its pinned deterministic URL scanner instead of this engine. Run only against targets you are authorized to test.

## Worker artifact contract

Each non-interactive run writes bounded machine-readable artifacts under `strix_runs/<run-name>/`:

- `run.json` records lifecycle, model/reasoning metadata, usage, limits, and reproducibility fields;
- `vulnerabilities.json` contains bounded structured finding candidates, control IDs, evidence metadata, and deterministic identities.

Deep scans use a deterministic two-tier route: the Terra/medium root owns coordination and cross-file judgment, while Luna/medium child specialists handle focused tasks with smaller output reservations. Only the root can create or stop specialists, so child work cannot fan out recursively. Child agents start with a focused task and system-owned scope instead of copying the full parent conversation unless the coordinator explicitly requests inherited context. Stable per-scan cache keys improve repeated-prefix reuse, and per-request usage receipts retain the actual model so mixed-model spend can be reconciled against the rate card.

The TypeScript worker treats all engine output as untrusted. It schema-validates these artifacts, never persists raw stdout/stderr, and does not allow model confidence to become independent verification proof. Existing artifact keys are compatibility-sensitive; coordinate changes with the worker contract tests in `lyrashield-ai`.

## Verification

Run the full gate before opening or approving a change:

```bash
bash scripts/verify-thin-fork.sh
```

The script name is retained for workflow compatibility; the repository is now maintained as a controlled derivative. The gate covers Ruff lint/format, 329 tests, headless mypy, Bandit, Python package and native-binary smoke, sandbox smoke, and the public worker contract.

These checks prove implementation compatibility, not detection accuracy. The inherited Strix v0.4 XBEN result is historical upstream evidence only. LyraShield must establish result quality with its own versioned evaluation corpus before making accuracy, coverage, or comparative claims; see [benchmarks/README.md](benchmarks/README.md).

## Upstream releases

`.lyrashield-upstream-base` records the incorporated upstream tree. Check upstream state with:

```bash
bash scripts/check-upstream.sh
```

The scheduled workflow compares stable release trees and prepares a review PR. Candidate upstream code is not executed in the write-enabled preparation job. Imports require human approval and the read-only engine CI gate; conflicts are never auto-resolved, history is never force-pushed, and the workflow never deploys.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). Upstream names and marks remain their owners' property.
