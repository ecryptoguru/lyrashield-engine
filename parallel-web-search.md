# Plan: Parallel Search Turbo web_search tool for LyraShield

## Context
User chose: inline agent tool, Parallel Search `turbo` default, accuracy-first redaction sanitizer.

## Goals
- Add a `web_search` tool backed by Parallel Search API (`/v1/search`).
- Keep main LLM as GPT-5.6 Terra/Luna; Parallel is only a research tool.
- Minimize data leakage via redaction, query shaping, and audit logging.
- Provide good UX in viewer + TUI and good DX via env vars + type-safe settings.

## Task dependency graph

```
1. Settings & config
   └── 2. web_search tool
       └── 3. Agent factory registration
       └── 4. Cost/budget hooks
   └── 5. TUI renderer
   └── 6. Viewer already ready (WebSearchRenderer exists)
7. Docs + product contract
8. Tests
9. Verification (ruff, mypy, pytest, .devin/scripts/checklist.py)
```

## Implementation checklist

- [ ] Add `WebSearchSettings` to `strix/config/settings.py` (LYRASHIELD_WEB_SEARCH_*).
- [ ] Create `strix/tools/web_search/tool.py` with redaction + Parallel Search call.
- [ ] Wire `web_search` into `strix/agents/factory.py` `_BASE_TOOLS`.
- [ ] Add web search cost tracking to `strix/core/hooks.py` / `strix/report/state.py`.
- [ ] Add TUI renderer `strix/interface/tui/renderers/web_search_renderer.py` and import in `__init__.py`.
- [ ] Update product contract: `docs/llm-providers/overview.mdx`, `docs/advanced/configuration.mdx`, `UPGRADES.md`.
- [ ] Write `tests/test_web_search.py` (unit: redaction, settings, tool output shaping).
- [ ] Run `ruff check`, `mypy`, `pytest`, `python .devin/scripts/checklist.py .`

## Key design decisions

- Endpoint: `https://api.parallel.ai/v1/search`, header `x-api-key`.
- Default mode: `turbo`, overridable per-call and via env.
- Query model: `topic`, `keywords`, `context`, `mode` — not free-form strings.
- Redaction: blocklist for secrets/PII/IPs; domain replaced with generic descriptor unless `public-endpoints` topic.
- Cost: fixed per-call reservation ($0.001 for turbo) plus actual observed cost.
