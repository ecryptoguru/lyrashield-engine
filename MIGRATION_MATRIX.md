# Strix Migration Matrix

- Target upstream: `v1.5.3` (`7cc9fa9faa0179fc7e35111102fe3d20a9028393`)
- Working branch: `codex/upstream-v1.5.3`
- Changed `strix/` paths: 2 files, +24/-0 lines relative to `v1.5.3`.

## Summary

`strix/**` has been advanced to the upstream `v1.5.3` tree. All product-specific code, prompts, tools, lifecycle hooks, policies, runtime, and interface extensions live under `lyrashield/**`.

The only remaining drift in `strix/` is two documented generic patches:

1. `strix/config/loader.py` — generic `register_settings_loader` / `load_settings` seam so product settings can be returned without upstream importing `lyrashield`.
2. `strix/skills/__init__.py` — telemetry-off gate in `_track_skill_loaded()`; v1.5.3 already supplies `register_skill_dir()`.

Every other `strix/` path is byte-identical to `v1.5.3`. In particular, `strix/agents/factory.py` and `strix/agents/prompt.py` are no longer local dispatchers.

## Matrix

| File | Purpose | Disposition |
|------|---------|-------------|
| `strix/config/loader.py` | Generic `register_settings_loader` / `load_settings` seam; product settings are returned transparently. | generic seam |
| `strix/skills/__init__.py` | Telemetry-off gate in `_track_skill_loaded()`; the directory registry itself is upstream. | generic fix |

All remaining `strix/` files are byte-identical to `v1.5.3`.

## LyraShield product directories

Product code now lives under `lyrashield/**`. The major directories and their ownership:

- `lyrashield/agents/` — product agent factory and prompt rendering.
- `lyrashield/artifacts/` — report deduplication, state, usage, writer, and SARIF handling.
- `lyrashield/interface/` — product CLI, TUI, viewer, and utility modules.
- `lyrashield/lifecycle/` — execution, hooks, runner, sessions, inputs, agent trust-boundary, and compaction logic.
- `lyrashield/policy/` — settings, model/provider policy, codex, loader, and provider-contract probes.
- `lyrashield/runtime/` — session manager, local directory staging, Docker client, and Caido bootstrap.
- `lyrashield/skills/` — product skill markdown overlays and the product `system_prompt.jinja`.
- `lyrashield/telemetry/` — product telemetry implementations (PostHog, Scarf, logging).
- `lyrashield/tools/` — product tool implementations (web search, todo, respond, reporting, proxy, agents graph, finish, notes, etc.).
- `lyrashield/utils/` — product redaction and shared utility helpers.
