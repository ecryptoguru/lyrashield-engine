# Contributing to LyraShield Engine

LyraShield Engine is a controlled derivative with a strict worker compatibility boundary. Keep changes focused, preserve attribution on modified upstream files, and do not broaden the supported model/provider surface.

## Development setup

Requirements: Python 3.12+, Docker, [uv](https://docs.astral.sh/uv/), and Git.

```bash
git clone https://github.com/ecryptoguru/lyrashield-engine.git
cd lyrashield-engine
uv sync --frozen
uv run lyrashield --version
uv run lyrashield --help
```

For an authorized local scan, configure an approved GPT-5.6 deployment:

```bash
export LYRASHIELD_LLM="openai/gpt-5.6-luna"
export LLM_API_KEY="<credential>"
export LLM_API_BASE="https://<approved-endpoint>"
uv run lyrashield --target ./approved-repository --scan-mode quick --non-interactive --max-budget-usd 1.20
```

Do not use paid model calls merely to verify documentation, packaging, or compatibility. The full deterministic gate does not require a paid scan.

## Where changes belong

- `lyrashield_adapter/`: public executable and `LYRASHIELD_*` compatibility aliases.
- `strix/`: reviewed derivative changes required for LyraShield model policy, bounded execution, lifecycle, identity, evidence, or artifact behavior. Retain the LyraShield modification banner on changed upstream Python files.
- `tests/`: regression coverage for every contract or behavior change.
- `scripts/` and `.github/workflows/`: deterministic verification and review-only release imports.
- Root documentation and `UPGRADES.md`: current ownership, operation, attribution, and divergence truth.

Avoid mechanical Strix-to-LyraShield rewrites. Generic upstream sandbox, tool, SDK, and skill behavior should remain close to the pinned release unless a concrete compatibility, safety, or product requirement justifies divergence.

## Pull requests

1. Branch from current `main`; use a focused `codex/` branch for Codex changes.
2. Make the smallest complete change and add regression tests.
3. Update `NOTICE`, `UPGRADES.md`, and user/operator docs when the supported contract or divergence changes.
4. Run `bash scripts/verify-thin-fork.sh` and `git diff --check`.
5. Open a PR; never push directly to `main`.
6. Require human review and green Engine CI before merge.

Artifact schema changes must also pass the public worker contract against `ecryptoguru/lyrashield-ai`. Do not remove or reinterpret existing fields without a coordinated compatibility release.

## Skills and upstream imports

Security skills live under `strix/skills/`. Changes must include practical, authorized test guidance and a method for distinguishing evidence from assumptions. A skill or prompt can improve behavior, but it is not proof of result quality; evaluation-corpus coverage is required for result claims.

Stable upstream releases are imported through the workflow described in [UPGRADES.md](UPGRADES.md). The workflow may arm GitHub's squash auto-merge only after requesting owner review; branch protection still requires that human approval and green Engine CI. Never bypass those gates, force-push, execute unreviewed candidate code in a write-enabled preparation job, or invent automatic conflict resolution.

## Issue reports

Include the engine commit/version, Python and Docker versions, host OS, sanitized command/target type, model family and reasoning effort (never credentials), relevant bounded artifact fields, and reproduction steps. Remove repository content, secrets, raw prompts/responses, and provider payloads before sharing logs.
