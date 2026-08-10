# Strix Migration Matrix

- Target upstream: `v1.5.2` (`597aae67159636ee794a02a3cc1694138d619c44`)
- Fork HEAD: `5f3093e4ae5eea2b59b826669d1f0cad7720dee2`
- Changed `strix/` paths: 4 files (4 unique paths), covering 72 insertions and 720 deletions relative to `v1.5.2`.

## Summary

`strix/**` has been reset to the upstream `v1.5.2` tree. All product-specific code, prompts, tools, lifecycle hooks, policies, runtime, and interface extensions now live under `lyrashield/**`.

The only remaining drift in `strix/` is four documented, generic, upstream-compatible seams:

1. `strix/agents/factory.py` — re-exports `lyrashield.agents.factory` and provides the generic `register_tool_override` / `register_agent_tools` seam.
2. `strix/agents/prompt.py` — re-exports `lyrashield.agents.prompt` (`render_system_prompt`, `_resolve_skills`) and provides a skill-directory-aware prompt-loading seam.
3. `strix/config/loader.py` — generic `register_settings_loader` / `load_settings` seam so product settings can be returned without upstream importing `lyrashield`.
4. `strix/skills/__init__.py` — telemetry-off gate in `_track_skill_loaded()` plus the existing `register_skill_dir()` seam.

Every other `strix/` path is byte-identical to `v1.5.2`.

## Matrix

| File | Purpose | Disposition |
|------|---------|-------------|
| `strix/agents/factory.py` | Re-exports `lyrashield.agents.factory` and exposes generic tool/agent registration seams (`register_agent_tools`, `register_tool_override`). | generic seam |
| `strix/agents/prompt.py` | Re-exports `lyrashield.agents.prompt` (`render_system_prompt`, `_resolve_skills`) and searches registered skill directories before built-in prompt templates. | generic seam |
| `strix/config/loader.py` | Generic `register_settings_loader` / `load_settings` seam; product settings are returned transparently. | generic seam |
| `strix/skills/__init__.py` | Telemetry-off gate in `_track_skill_loaded()` and the existing `register_skill_dir()` seam. | generic seam |

All remaining `strix/` files are reset to `v1.5.2`.

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
