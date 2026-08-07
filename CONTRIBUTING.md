# Contributing to LyraShield Engine

LyraShield Engine is a controlled derivative of [Strix](https://github.com/usestrix/strix) v1.4.1, pinned at upstream base `2e70402` and modified under Apache-2.0. See [NOTICE](NOTICE) for attribution and [UPGRADES.md](UPGRADES.md) for the ownership and upstream-import ledger. This guide covers changes to the engine itself; the [LyraShield AI application repository](https://github.com/ecryptoguru/lyrashield-ai) owns product UX, worker, evidence state, and reporting.

## Development setup

### Prerequisites

- Python 3.12+
- Docker (running)
- [uv](https://docs.astral.sh/uv/) (dependency management)
- Git
- a reviewed sandbox image (see `docs/tools/sandbox.mdx`)

### Local development

1. **Clone the repository**

   ```bash
   git clone https://github.com/ecryptoguru/lyrashield-engine.git
   cd lyrashield-engine
   ```

2. **Install dependencies**

   ```bash
   uv sync --frozen
   uv run pre-commit install
   ```

3. **Configure an approved GPT-5.6 Terra or Luna endpoint**

   ```bash
   export LYRASHIELD_LLM="openai/gpt-5.6-luna"
   export LLM_API_KEY="<credential>"
   export LLM_API_BASE="https://<approved-endpoint>"
   ```

   Only GPT-5.6 Terra and Luna deployments are accepted at the product boundary. Anthropic, Bedrock, Vertex, OpenRouter, Novita, local models, Perplexity, Parallel, and ChatGPT subscription-backed models are unsupported and rejected. See the [configuration reference](docs/advanced/configuration.mdx).

4. **Run the engine against an authorized repository target**

   ```bash
   uv run lyrashield --target ./approved-repository --scan-mode quick --non-interactive --max-budget-usd 1.20
   ```

   The production entry point is `lyrashield`, not the upstream `strix` executable. The adapter (`lyrashield_adapter`) forces telemetry off, disables the upstream self-update check, rejects `chatgpt/` subscription models, and sets `LYRASHIELD_PRODUCT_BOUNDARY` so configuration is re-validated after `--config` is applied.

## Ownership boundary

Preserve the reviewed boundary between LyraShield-owned product behavior and the retained upstream substrate.

**LyraShield owns:** GPT-5.6 Terra/Luna acceptance and reasoning policy; context compaction, output/agent limits, and concurrent pre-request spend reservations; non-interactive lifecycle, cancellation, cleanup, telemetry-off defaults, and target-safe errors; deterministic finding identity, structured control/evidence metadata, and bounded artifacts; the worker-facing `run.json` and `vulnerabilities.json` contract.

**Retained upstream substrate:** generic sandbox/session mechanics, security tools, agent-SDK integration, and the vulnerability skill library.

New changes should keep that boundary: extract LyraShield policy behind explicit modules and versioned artifacts when useful, without rewriting stable upstream infrastructure.

## Required workflow

1. Branch from `main`; never push directly to `main`.
2. Keep generic upstream sandbox/tool/SDK plumbing close to the pinned Strix release.
3. Put LyraShield model, budget, lifecycle, identity, evidence, and artifact behavior behind explicit reviewed boundaries.
4. Preserve the one-line LyraShield modification banner on every changed `strix/` source file:

   ```python
   # Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
   ```

5. Add tests and update `NOTICE`, `UPGRADES.md`, and operator docs when the contract changes.
6. Run the verify gate and check for whitespace errors:

   ```bash
   bash scripts/verify-controlled-derivative.sh
   git diff --check
   ```

   The gate runs Ruff lint/format, the full `pytest` suite, headless mypy (excluding the upstream TUI), Bandit on `strix` and `lyrashield_adapter`, Python package and native-binary smoke, sandbox smoke, and the public worker contract. It also diffs `strix/**` against the pinned upstream base and fails on any file that lacks both the attribution banner and a `UPGRADES.md` entry, preventing undocumented `strix/` drift. A **footprint budget** check warns (does not fail) when `strix/**` drift exceeds the configured thresholds (max 80 files, +8000 insertions, -2000 deletions), so accumulated drift stays visible.

7. Require human approval and green Engine CI before merge. Engine CI (`.github/workflows/ci.yml`) now enforces the same quality gates as pre-commit on every pull request and push to `main`: Ruff lint and format check, Mypy type check, Bandit security scan, and the full pytest test suite (597 tests). Using `--no-verify` to skip pre-commit hooks no longer bypasses quality gates — CI will catch the same issues and block the merge.

## Pull request guidelines

- Create an issue first for non-trivial changes.
- Keep PRs small and focused: one feature or fix per PR.
- Follow existing code style: PEP 8 with a 100-character line limit, type hints on all functions, docstrings on public methods.
- Include tests for new behavior and update documentation when the contract changes.
- Link the PR to its issue and explain what changed and why.

## Contributing skills

Skills are structured knowledge packages that give engine agents task-specific vulnerability, technology, and testing context. The catalog lives under `strix/skills/` and is part of the controlled derivative. See [docs/advanced/skills.mdx](docs/advanced/skills.mdx) for the catalog and structure.

When changing skills:

- Keep the LyraShield modification banner on changed upstream skill files.
- Add regression coverage if a skill affects agent behavior or tool selection.
- Update `UPGRADES.md` and operator docs when the catalog or skill contract changes.
- Do not add skills that re-enable telemetry, broaden provider support, or declare confidence equivalent to verification.

## Local viewer SPA

`lyrashield view` (inherited from upstream `strix view`) serves a prebuilt web UI whose source lives in `strix/interface/viewer/frontend/` (a Vite + React project) and whose built output is committed to `strix/interface/viewer/static/` and shipped in the package. End users never run a JS build. If you change anything under `strix/interface/viewer/frontend/`, rebuild and commit the output:

```bash
make viewer   # or: cd strix/interface/viewer/frontend && npm ci && npm run build
```

Commit both the source change and the regenerated `strix/interface/viewer/static/`.

## Reporting issues

When reporting bugs, include:

- Python version and OS
- LyraShield Engine version (`uv run lyrashield --version`)
- The approved GPT-5.6 deployment and reasoning effort
- Full error traceback
- Steps to reproduce
- Expected vs actual behavior

Never include real credentials, target secrets, customer data, or unapproved proprietary repositories in an issue.

## Constraints

<Warning>
Do not add providers or models outside GPT-5.6 Terra and Luna; re-enable telemetry; weaken budget reservations; persist raw model output; or make confidence equivalent to verification.
</Warning>

Artifact schema changes (`run.json`, `vulnerabilities.json`) require coordinated worker compatibility testing against `ecryptoguru/lyrashield-ai`.

## Security hardening

The engine includes a comprehensive security hardening pass (see `AI_AUDIT_REPORT.md` for the full audit and `UPGRADES.md` for the ledger). When contributing changes that touch security-sensitive areas:

- **Trust boundaries:** Do not remove or weaken `[SYSTEM-NOTICE]` or `[SYSTEM-VERIFIED PEER MESSAGE]` tags from the system prompt or message wrapping code. Tags must only be valid at the start of a top-level user message from the platform.
- **Secret redaction:** Do not bypass `redact_text()` calls in `ReportState.add_vulnerability_report`, `ReportState.update_scan_final_fields`, or `maybe_compact`. PoC script code must always preserve internal paths for reproducibility.
- **Path redaction:** Do not remove the `_is_whitebox` mode-aware path redaction logic. Spill paths (`/workspace/.strix/tool-output/`) and tmp state (`/tmp/.strix`) must always be redacted.
- **Telemetry:** Do not hardcode telemetry keys. Use the lazy `_posthog_api_key()`, `_posthog_host()`, and `_scarf_endpoint()` helpers that read from environment variables at call time. Do not spawn telemetry threads when `telemetry.enabled` is false.
- **Prompt sanitization:** Do not bypass `_sanitize_prompt_value` for `root_instructions_override`, `extra_system_prompt_context`, or target values. The regex must cover `{{ }}`, `{% %}`, and `{# #}` Jinja tags.
- **Dedupe schema:** Do not remove `AgentOutputSchema(strict_json_schema=True)` from the dedupe model call. The fallback lenient parser must remain for resilience.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). Upstream names and marks remain their owners' property.
