# `lyrashield` package

This package holds all LyraShield product-critical behavior: model policy,
lifecycle, budget hooks, tools, skills, interface, telemetry and the
worker artifact contract. The retained `strix/**` substrate is the upstream
release pinned in the repository-root `.lyrashield-upstream-base` (v1.6.2),
imported with only the reviewed modifications listed in
`scripts/verify-controlled-derivative.sh`. Carrier code outside `lyrashield/**`
retains the upstream attribution documented in `NOTICE`.

## Module map

| Module | Contents |
| --- | --- |
| `lyrashield/policy/` | GPT-6 model acceptance (the provider allowlist that refuses subscription routes), reasoning policy, `LYRASHIELD_*` env aliases, provider-contract probing |
| `lyrashield/lifecycle/` | Non-interactive agent loop, execution, budget hooks, context compaction, prompt sanitization, cancellation, sessions |
| `lyrashield/runtime/` | Sandbox session, Docker client, Caido bootstrap, local-dir staging |
| `lyrashield/agents/` | Product agent factory, programmatic tool calling, output-store binding, redaction, system-prompt renderer |
| `lyrashield/interface/` | Product CLI, auth CLI, provider-contract CLI, TUI, viewer SPA, update check |
| `lyrashield/artifacts/` | Report state, dedupe, SARIF, writer, usage accounting — the `run.json` / `vulnerabilities.json` contract |
| `lyrashield/telemetry/` | Lazy-key PostHog/Scarf clients with forced-off production defaults |
| `lyrashield/utils/` | Mode-aware path and secret redaction |
| `lyrashield/tools/` | Product tool overrides: web_search, proxy, reporting, respond, todo, agents_graph, finish, notes, thinking, load_skill, output_store |
| `lyrashield/skills/` | Product skill overlays and the product system-prompt Jinja template |

## Registration seams

Product modules register themselves through generic seams in the retained
`strix/**` substrate:

- `strix.skills.register_skill_dir` — loads `lyrashield/skills/` alongside
  inherited `strix/skills/`.
- `strix.agents.factory.register_tool_override` — replaces upstream base tools
  with product implementations from `lyrashield/tools/`.
- `strix.agents.factory.register_model_policy` — registers the product
  GPT-6 model-acceptance policy from `lyrashield/policy/models.py`.
- `strix.config.loader.register_settings_loader` — registers
  `lyrashield/policy/loader.py` as the product settings loader.
- `strix.agents.prompt.FileSystemLoader` — searches registered skill
  directories before `strix/agents/prompts/`, so
  `lyrashield/skills/system_prompt.jinja` overrides the upstream template.

All registrations are wired from `lyrashield_adapter/cli.py` before
delegating to the upstream `main()`.

Changes are tracked in `UPGRADES.md` and the `NOTICE` file.
