# Contributing to LyraShield Engine

LyraShield Engine is a controlled derivative of [Strix](https://github.com/usestrix/strix) v1.5.3, pinned at upstream base `7cc9fa9faa0179fc7e35111102fe3d20a9028393` and modified under Apache-2.0. See [NOTICE](NOTICE) for attribution and [UPGRADES.md](UPGRADES.md) for the ownership and upstream-import ledger. This guide covers changes to the engine itself; the [LyraShield AI application repository](https://github.com/ecryptoguru/lyrashield-ai) owns product UX, worker, evidence state, and reporting.

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

   Metered scans accept GPT-5.6 Terra and Luna deployments from the supported provider allowlist. Authenticated `chatgpt/*` subscription runs are also supported by default and can be disabled with `LYRASHIELD_ALLOW_CHATGPT_SUBSCRIPTION=0`. See the [configuration reference](docs/advanced/configuration.mdx) for the exact routes and accounting behavior.

4. **Run the engine against an authorized repository target**

   ```bash
   uv run lyrashield --target ./approved-repository --scan-mode quick --non-interactive --max-budget-usd 1.20
   ```

   The production entry point is `lyrashield`, not the upstream `strix` executable. The adapter (`lyrashield_adapter`) forces telemetry off, disables the upstream self-update check, applies product aliases and provider policy, and sets `LYRASHIELD_PRODUCT_BOUNDARY` so configuration is re-validated after `--config` is applied.

## Ownership boundary

Preserve the reviewed boundary between LyraShield-owned product behavior and the retained upstream substrate.

**LyraShield owns:** GPT-5.6 Terra/Luna acceptance and reasoning policy; context compaction, output/agent limits, and concurrent pre-request spend reservations; non-interactive lifecycle, cancellation, cleanup, telemetry-off defaults, and target-safe errors; deterministic finding identity, structured control/evidence metadata, and bounded artifacts; the worker-facing `run.json` and `vulnerabilities.json` contract.

**Retained upstream substrate:** generic sandbox/session mechanics, security tools, agent-SDK integration, and the vulnerability skill library.

New changes should keep that boundary: extract LyraShield policy behind explicit modules and versioned artifacts when useful, without rewriting stable upstream infrastructure.

## Required workflow

1. Branch from `main`; never push directly to `main`.
2. Keep generic upstream sandbox/tool/SDK plumbing close to the pinned Strix release.
3. Put LyraShield model, budget, lifecycle, identity, evidence, and artifact behavior behind explicit reviewed boundaries.
4. Do not add another `strix/**` modification without a reviewed upstream-compatibility reason. The current hard allowlist contains only `strix/config/loader.py` and `strix/skills/__init__.py`. Preserve the one-line LyraShield modification banner on those files:

   ```python
   # Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
   ```

5. Add tests and update `NOTICE`, `UPGRADES.md`, and operator docs when the contract changes. The application repository owns worker-image publication and VM promotion: merge and green Engine CI are necessary but do not update production by themselves. A reviewed application release must verify the immutable worker digest, and an operator must explicitly promote and reconcile it on the dedicated VM.
6. Run the verify gate and check for whitespace errors:

   ```bash
   bash scripts/verify-controlled-derivative.sh
   git diff --check
   ```

   The gate runs Ruff lint/format, the full `pytest` suite, headless mypy (excluding the upstream TUI), Bandit, Python package and native-binary smoke, sandbox smoke, and the public worker contract. It diffs `strix/**` against the pinned v1.5.3 base and fails on any path outside the two-file allowlist, more than 30 insertions, or any deletion. It also validates attribution and the `UPGRADES.md` ledger.

7. Require human approval and green Engine CI before merge. Engine CI (`.github/workflows/ci.yml`) enforces the same quality gates on every pull request and push to `main`. Test counts are intentionally omitted because the executable gate is authoritative.

## Dependency updates

Use `uv sync --frozen` for normal development. LiteLLM is a direct, exactly pinned dependency because LyraShield imports its routing, cost, cache, and provider-validation APIs; change that pin only in a focused upgrade with the full controlled-derivative and worker-contract gates. `certifi` is a transitive public CA bundle used by the HTTP stack and should not be promoted to a direct dependency unless LyraShield imports it. Review both `pyproject.toml` and `uv.lock` diffs, including hashes and newly introduced packages, in every dependency PR.

## Pull request guidelines

- Create an issue first for non-trivial changes.
- Keep PRs small and focused: one feature or fix per PR.
- Follow existing code style: PEP 8 with a 100-character line limit, type hints on all functions, docstrings on public methods.
- Include tests for new behavior and update documentation when the contract changes.
- Link the PR to its issue and explain what changed and why.

## Contributing skills

Skills are structured knowledge packages that give engine agents task-specific vulnerability, technology, and testing context. Inherited skills live under `strix/skills/`; LyraShield additions and overrides live under `lyrashield/skills/` and are registered through the supported seam. See [docs/advanced/skills.mdx](docs/advanced/skills.mdx) for the catalog and structure.

When changing skills:

- Keep the LyraShield modification banner on changed upstream skill files.
- Add regression coverage if a skill affects agent behavior or tool selection.
- Update `UPGRADES.md` and operator docs when the catalog or skill contract changes.
- Do not add skills that re-enable telemetry, broaden provider support, or declare confidence equivalent to verification.

## Local viewer SPA

`lyrashield view` (inherited from upstream `strix view`) serves a prebuilt web UI whose source lives in `lyrashield/interface/viewer/frontend/` and whose built output is committed under `lyrashield/interface/viewer/static/`. Treat both as upstream substrate: viewer changes may enter only through an approved upstream-base update documented in `UPGRADES.md`. Do not edit or commit inherited viewer source or generated output directly.

When an approved upstream-base update changes the viewer, retain the upstream source and generated output exactly as imported and let the controlled-derivative gate verify the resulting tree.

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

The engine includes a comprehensive security hardening pass (see the [Security hardening pass](UPGRADES.md#security-hardening-pass-2026-08-05) section in `UPGRADES.md` for the full audit and ledger). When contributing changes that touch security-sensitive areas:

- **Trust boundaries:** Do not remove or weaken `[SYSTEM-NOTICE]` or `[SYSTEM-VERIFIED PEER MESSAGE]` tags from the system prompt or message wrapping code. Tags must only be valid at the start of a top-level user message from the platform.
- **Secret redaction:** Do not bypass `redact_text()` calls in `ReportState.add_vulnerability_report`, `ReportState.update_scan_final_fields`, or `maybe_compact`. PoC script code must always preserve internal paths for reproducibility.
- **Path redaction:** Do not remove the `_is_whitebox` mode-aware path redaction logic. Spill paths (`/workspace/.strix/tool-output/`) and tmp state (`/tmp/.strix`) must always be redacted.
- **Telemetry:** Do not hardcode telemetry keys. Use the lazy `_posthog_api_key()`, `_posthog_host()`, and `_scarf_endpoint()` helpers that read from environment variables at call time. Do not spawn telemetry threads when `telemetry.enabled` is false.
- **Prompt sanitization:** Do not bypass `_sanitize_prompt_value` for `root_instructions_override`, `extra_system_prompt_context`, or target values. The regex must cover `{{ }}`, `{% %}`, and `{# #}` Jinja tags.
- **Dedupe schema:** Do not remove `AgentOutputSchema(strict_json_schema=True)` from the dedupe model call. The fallback lenient parser must remain for resilience.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). Upstream names and marks remain their owners' property.
