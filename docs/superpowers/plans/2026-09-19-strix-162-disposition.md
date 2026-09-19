# Strix v1.6.2 controlled import — commit/path disposition ledger

Task 7 of `2026-09-19-production-engine-app-handoff.md`.

- Base: `7cc9fa9faa0179fc7e35111102fe3d20a9028393` (v1.5.3, pinned in `.lyrashield-upstream-base`)
- Target: `ff5c8cc8e46d8e60c2bc2439f7bcb07c05ca3db2` (`git rev-parse 'v1.6.2^{commit}'`, verified 2026-09-19)
- Method: tree delta `git diff v1.5.3..v1.6.2 | git apply --3way` (squashed fork history; no `git merge`).
- Inventory: `git log --no-merges v1.5.3..v1.6.2` = **86 commits** (verified).

Dispositions: `ADOPT_SUBSTRATE` (upstream `strix/**` content lands verbatim),
`PORT_OWNED` (behavior also ported into owned `lyrashield/**` code),
`ALREADY_EQUIVALENT` (owned code already covers it / no-op for this fork),
`EXCLUDE_PRODUCT` (product wiring rejected; substrate files may still land for
tree parity but stay unreachable from the `lyrashield` entry point),
`DEFER_WITH_REASON` (not in this import; reason recorded).

## Commit dispositions (newest first, `git log` order)

| Commit | Subject | Disposition | Justification |
|---|---|---|---|
| ff5c8cc8 | chore: release v1.6.2 | ALREADY_EQUIVALENT | Version bump only; owned `pyproject.toml`/`uv.lock` carry product versioning. |
| afce7d95 | fix(telemetry): classify setup-mode TUI preflight failures | ADOPT_SUBSTRATE | Telemetry substrate; product forces `STRIX_TELEMETRY=0` at the boundary. |
| 2e1db257 | feat(telemetry): classify error beacons by phase/exception | ADOPT_SUBSTRATE | Same; `_common.py` gains `exception_props`/scan-phase helpers. Protocol seam re-applied. |
| f4b0416b | docs: update README and CLI links (#1272) | ADOPT_SUBSTRATE | `strix/` viewer assets + `cli_args.py` links land; owned README/docs/install.sh paths excluded. |
| c2c84f11 | chore(telemetry): drop lock around loaded-skills set | ADOPT_SUBSTRATE | Substrate cleanup; no product surface. |
| bb7e82b6 | chore(telemetry): drop per-load skill_loaded beacons | ADOPT_SUBSTRATE | `_track_skill_loaded` now only fills a set — lets us DROP the fork's telemetry gate in `strix/skills/__init__.py` (genuinely equivalent: nothing sent at load). |
| 9cc9de8c | fix(warmup): drop docker from WARMUP_MODULES | ADOPT_SUBSTRATE | Startup perf; substrate-only file `strix/llm/warmup.py` (new). |
| a3bf864e | test(warmup): assert wait_for_import_warmup blocks | ADOPT_SUBSTRATE | Test adopted with warmup feature. |
| e60fd839 | refactor(warmup): drop orphan purge, join warmup once | ADOPT_SUBSTRATE | Same feature line. |
| 7f46dd17 | fix(cli): wait for import warm-up before agents SDK import | ADOPT_SUBSTRATE | `strix/interface/main.py` is substrate; product CLI is `lyrashield/interface/main.py`. |
| afa7c4a7 | feat(web_search): Exa provider alongside Perplexity | ADOPT_SUBSTRATE | Substrate tool/settings land; product registers owned Parallel `web_search` override — upstream providers unreachable. Env check change in `environment.py` rides along. |
| f6d9790e | fix(viewer): show stopped run status | ADOPT_SUBSTRATE | Substrate viewer; product viewer is owned `lyrashield/interface/viewer/`. |
| 5d015df6 | fix(cloud): top-up instructions on 402 | EXCLUDE_PRODUCT | Cloud/billing feature rejected; `strix/interface/cloud/` files land only for tree parity, unreachable (product CLI never dispatches `cloud`). |
| 1edafd3e | fix(agents): stop parents waiting on finished non-interactive children | PORT_OWNED | Ported into `lyrashield/lifecycle/agents.py` (`resumable`, `_unreachable_locked`, `reachability`, send drop), `lyrashield/lifecycle/execution.py` (`resumable=interactive`), `lyrashield/tools/agents_graph/tools.py` (delivery_status, wait_outcome=no_active_agents, filed_report_ids). Substrate version lands too. |
| f1e24fe3 | chore: release v1.6.1 | ALREADY_EQUIVALENT | Version bump only. |
| e644f4a0 | docs(readme): shorten coding-agent skills paragraph | EXCLUDE_PRODUCT | Owned README; upstream marketing copy not applicable. |
| 1ebe1007 | docs: keep recommended model rows in README | EXCLUDE_PRODUCT | Owned README + owned model policy (`lyrashield/policy/models.py` GPT-5.6 Terra/Luna). |
| 53d2e5cf | docs: viewer steering/history/report prerequisites | EXCLUDE_PRODUCT | Owned docs. |
| 7708f717 | docs: trim README, add cloud CLI/viewer docs pages | EXCLUDE_PRODUCT | Owned docs; cloud CLI docs rejected with the feature. |
| a8642de7 | docs(readme): trim strix cloud section | EXCLUDE_PRODUCT | Owned README. |
| 75b89018 | docs: openrouter/z-ai/glm-5.3 default in examples | ADOPT_SUBSTRATE | `strix/interface/environment.py` setup-hint change lands; docs/README/AGENTS.md excluded (owned). Product model gate unaffected. |
| 129f9380 | fix(models): aggregator routes out of RECOMMENDED_MODEL_NAMES | ADOPT_SUBSTRATE | Substrate model catalog only; product policy is owned allowlist. |
| b438632e | fix(models): additions-only list, glm-5.3 top pick | ADOPT_SUBSTRATE | Same; `auth_cli.py`/environment hunks land but auth CLI is unwired at boundary. |
| 0ab72448 | feat(models): refresh recommended model list | ADOPT_SUBSTRATE | Same reasoning; no provider expansion at product boundary. |
| c514f712 | fix(config): persist only the alias the runtime reads | PORT_OWNED | Ported to `lyrashield/policy/loader.py::persist_current` (writes only the active alias, clears sibling aliases). |
| 3e88e498 | fix(config): drop stored LLM connection when linked env var changes | PORT_OWNED | Ported `_LINKED_LLM_FIELDS`/`_drop_stale_llm_connection`/`_first_alias_value` to owned loader. |
| ce0db302 | fix(config): merge env into cli-config.json instead of overwriting | PORT_OWNED | Owned `persist_current` now merges into the existing env block (stored-config preservation). |
| 941c9606 | fix(ci): pre-commit mypy + fresh-checkout tests | ADOPT_SUBSTRATE | Substrate typing fixes land (codex.py, runner.py, state.py, cloud/__init__); owned `.pre-commit-config.yaml`/`pyproject.toml` hand-ported where relevant. |
| 46b4e6cb | fix(tui): env/model checks on no-target start screen | ADOPT_SUBSTRATE | Substrate TUI/backend; product TUI is owned. |
| b5c3807f | fix(mcp): keep session on protocol errors, truthful quarantine | ADOPT_SUBSTRATE | MCP substrate; not wired into product toolset. |
| 42baa7c0 | skills: point to strix cloud CLI in every skill | EXCLUDE_PRODUCT | Top-level `skills/` coding-agent packages are not shipped by this fork; content pushes the rejected cloud CLI. |
| 8fdf6a5c | chore: release v1.6.0 | ALREADY_EQUIVALENT | Version bump only. |
| 46cf2f52 | report: add update_vulnerability_report (#1210) | ADOPT_SUBSTRATE | Lands in substrate (`strix/tools/reporting/tool.py`, report state/writer). Product reporting tool is the owned override; revision-history invariants are Task 8 scope (Open #1307). |
| 3de94714 | Link CLI wallet (#1222) | EXCLUDE_PRODUCT | Wallet/billing wiring rejected; files land as unreachable substrate. |
| a0710221 | Forward workspace header through wallet payment bridge | EXCLUDE_PRODUCT | Same. |
| d26b1ab0 | pentest skill cloud cli (#1220) | EXCLUDE_PRODUCT | Top-level `skills/` not shipped. |
| de730119 | feat(cli): strix cloud — managed platform CLI | EXCLUDE_PRODUCT | Login/scans/billing CLI rejected; substrate files land unreachable. Product never dispatches `cloud`/`platform_cli`. |
| 608ef4a3 | MCP connections survive transient transport failures | ADOPT_SUBSTRATE | MCP substrate resilience; unwired in product. |
| f901d2a8 | fix(runtime): drop staged extra files on pre-cache failure | ADOPT_SUBSTRATE | Substrate session_manager; owned runtime has its own staging lifecycle (Task 3). |
| 944274e1 | fix(runtime): remove extra-file staging dir on cleanup | ADOPT_SUBSTRATE | Same. |
| eeca4047 | fix(runtime): stage extra-file binds under temp dir | ADOPT_SUBSTRATE | Same; also fixes remote-docker path resolution. |
| 1df67c52 | fix(viewer): harden PDF report rendering (#1192) | PORT_OWNED | markdown-it-py token rendering, `_normalize_text`, severity normalization, duration overflow guard ported to `lyrashield/interface/viewer/report_pdf.py`; `markdown-it-py` added to viewer extra. Substrate version lands with our `_startPage` getattr guard re-applied. |
| 3c767cdd | csv injection hardening (#1203) | ADOPT_SUBSTRATE | Substrate `strix/report/{state,writer}.py`; owned artifacts already have CSV formula safety (pre-existing equivalent). |
| 0a6e8b01 | Fix user message retry lifecycle and TUI sync | ADOPT_SUBSTRATE | Substrate agents/TUI backend. |
| 1f3f9b31 | fix(report): keep strix.report import-light vs warmup race | ADOPT_SUBSTRATE | Import-order hardening; complements our Protocol seam in telemetry. |
| cf179d56 | fix(llm): bind dedupe credentials to provider; reasoning=max via extra_body | PORT_OWNED | Owned `lyrashield/artifacts/dedupe.py` had the same colliding `extra_args` credential pattern upstream removed; ported `resolve_dedupe_model` (provider-bound creds). |
| 583af23d | fix(llm): prompt-cache points only on LiteLLM routes | PORT_OWNED | Owned `_prompt_cache_extra_args` had the same leak (bare `claude-*` names served by the SDK client got LiteLLM-only kwargs → TypeError). Ported `routes_through_litellm` gate into `lyrashield/policy/models.py` + `lyrashield/lifecycle/inputs.py`. |
| 717ffc8f | Isolate MCP connections per task, surface status in UIs | ADOPT_SUBSTRATE | MCP substrate + viewer/TUI renderers. |
| cbb0f570 | Reach MCP tools on demand (describe/call dispatch) | ADOPT_SUBSTRATE | Same; `pyproject` mcp marker deps ride transitively via openai-agents. |
| 8b655de6 | Mirror run threat models into state dir for resume | ADOPT_SUBSTRATE | Substrate runner/threat_model tool. |
| 7d8d71be | Scope threat models to current run | ADOPT_SUBSTRATE | Same. |
| a5856108 | fix(tui): restore base foreground after ANSI resets | ADOPT_SUBSTRATE | Go TUI substrate. |
| bfaaa904 | fix(update): re-exec new binary after self-update | ADOPT_SUBSTRATE | Substrate update_check; product disables `--update` in owned interface — unreachable. |
| 187f41f3 | Treat 'null'/'none' strings as absent for optional tool args | PORT_OWNED | `strix/tools/nullish.py` lands; `clean_optional` calls ported into owned `lyrashield/tools/proxy/tools.py` (list_requests/list_sitemap) and `lyrashield/tools/reporting/tool.py` (`_do_list_reports` filters). Product uses owned factory (no `_coerce_arguments` layer) so the schema-level coercion stays substrate-only. |
| f4ef8867 | Add MCP server support (#1137) | ADOPT_SUBSTRATE | `strix/tools/mcp/**`, cli_args flag; product boundary does not expose `--mcp-config` (owned CLI args). |
| 391d81be | feat(agents): evidence discipline + coverage artifact (#961) | ADOPT_SUBSTRATE | Coverage/threat-model tools, analysis skills (counterevidence, fix_verification, severity_calibration, source_aware_discovery), substrate prompt/SARIF/state. Owned evidence schema is Task 8 scope. |
| 1c499c5b | perf: bootstrap Caido concurrently with scan start | ADOPT_SUBSTRATE | Substrate runtime (`caido_handle.py` new); owned runtime keeps its serialized bootstrap semantics (Task 3 lifecycle). |
| 1ce43d1b | perf: heavy imports off startup path + warmup thread | ADOPT_SUBSTRATE | `strix/llm/warmup.py`, lazy imports in execution/compaction/context_budget/caido_api/pricing. |
| 2cc81678 | docs(skills): gRPC guidance correction | EXCLUDE_PRODUCT | Top-level `skills/` not shipped. |
| d6a3ca7e | docs(skills): document --workspace-file | EXCLUDE_PRODUCT | Same. |
| 9099710c | docs(skills): fix --mount flag, add application-security-testing | EXCLUDE_PRODUCT | Same. |
| 634cb982 | docs(skills): OWASP Top 10:2025, API Top 10 2023 | EXCLUDE_PRODUCT | Same; taxonomy validated separately (see skills section). |
| 1b36343e | fix(skills): unquoted colon in api-security-testing desc | EXCLUDE_PRODUCT | Same. |
| b5ef93e7 | feat(skills): target-specific testing skills | EXCLUDE_PRODUCT | Top-level `skills/` SKILL packages not shipped. |
| e152c4c7 | fix(report): RuntimeError on non-object run.json | ADOPT_SUBSTRATE | cli_args validation substrate. |
| fe758af4 | fix(tui): single space after ordered-list marker | ADOPT_SUBSTRATE | Go TUI renderer. |
| deb2057e | fix(tui): preserve cost when state truncated | ADOPT_SUBSTRATE | Substrate TUI projection. |
| d6f22187 | Drop strict tool schemas on Claude routes | ADOPT_SUBSTRATE | Substrate factory/models; product model policy unaffected. |
| 6f88b7d7 | Require viewer session for run data | PORT_OWNED | Substrate viewer server lands it; owned `lyrashield/interface/viewer/server.py` had the same launched-run hole (session only gated *other* runs) — ported the all-data session gate. |
| 8d3693df | Expose viewer host option | ADOPT_SUBSTRATE | Substrate viewer CLI. |
| 9cd81e5c | Add semantic browser + Electron security skills | ADOPT_SUBSTRATE | `electron_desktop_apps`, `browser_security`, `semantic_confusion` + updates land under `strix/skills/`; `semantic_confusion.md`'s dead `load hurl`/`load hypothesis` references rewritten to plain harness guidance since those skills are excluded. |
| e8272c6a | Add HTTP differential testing tools | EXCLUDE_PRODUCT | `strix/skills/tooling/{hurl,hypothesis}.md` stay OUT: sandbox image (`containers/`) ships neither hurl nor hypothesis; an agent could not run them. Recorded as reviewed deletions in the gate allowlist. |
| aa5867f5 | Add ecosystem supply-chain security skills | ADOPT_SUBSTRATE | `npx_confusion`, `infrastructure_lifecycle`, `agentic_system_security`, `llm_prompt_injection`, `subdomain_takeover` updates. |
| 7b8f9cb1 | Add argument injection security skill | ADOPT_SUBSTRATE | `argument_injection.md` + `rce.md` update. |
| 2d944a9b | Add Azure and Entra security skill | ADOPT_SUBSTRATE | `cloud/azure.md`. |
| 0478a69a | feat(skills): cover OWASP LLM Top 10 2026 | ADOPT_SUBSTRATE | `llm_applications.md`, `llm_prompt_injection.md`, `deep.md`, `source_aware_sast.md`; OWASP LLM Top 10 2026 taxonomy matches the published 2026 edition. |
| 8ede419d | handle resume tokens gracefully (#1097) | ADOPT_SUBSTRATE | report/state + telemetry resume handling. |
| a46a60cf | feat(reporting): contextual CVSS + usage evidence on dep reports | ADOPT_SUBSTRATE | Substrate reporting tool + dependency_cve_scanning skill; owned reporting tool keeps its CVSS calibration (Task 8 consumes fields). |
| 918442db | cli: render contextual CVSS vector/advisory/reasoning | ADOPT_SUBSTRATE | `strix/interface/utils.py` render helper (uses markdown-it-py). |
| e442db9c | Contextual CVSS as full 8-metric breakdown | ADOPT_SUBSTRATE | report writer + reporting tool substrate. |
| 9c0d30a0 | reporting: source-to-sink trace in reachability evidence | ADOPT_SUBSTRATE | Substrate reporting tool + skill. |
| 55e6e660 | reporting: contextual CVSS in markdown report | ADOPT_SUBSTRATE | Substrate writer/tool. |
| 99e2d5d8 | reporting: drop per-metric CVSS reasoning | ADOPT_SUBSTRATE | Same. |
| 310f310e | feat(reporting): contextual CVSS environmental metrics | ADOPT_SUBSTRATE | Same. |
| 85513391 | feat: caller-provided files into sandbox (`extra_files`, `--workspace-file`) | ADOPT_SUBSTRATE | Substrate inputs/runner/session/cli_args; product CLI does not expose `--workspace-file` (Task 9 owns attachments). |
| 8ca0c4a9 | Fix LiteLLM cost model resolution | ADOPT_SUBSTRATE | New `strix/report/pricing.py`; owned cost accounting in `lyrashield/artifacts/usage.py` unchanged (never replaced). |

## Path dispositions (grouped)

### Adopted substrate (`strix/**` — must equal upstream except allowlisted seams)

| Path | Disposition |
|---|---|
| `strix/interface/cloud/**`, `strix/interface/{platform_cli,platform_identity,completions,terminal_text,url_safety}.py` | ADOPT_SUBSTRATE files; EXCLUDE_PRODUCT wiring — unreachable from `lyrashield` entry point |
| `strix/tools/mcp/**` | ADOPT_SUBSTRATE; product CLI/factory do not wire MCP connections |
| `strix/tools/{coverage,threat_model}/**`, `strix/tools/nullish.py` | ADOPT_SUBSTRATE; product wiring is a later-task decision |
| `strix/llm/warmup.py`, `strix/report/{coverage,pricing}.py`, `strix/runtime/caido_handle.py` | ADOPT_SUBSTRATE (new modules) |
| `strix/skills/analysis/*` (counterevidence, fix_verification, severity_calibration, source_aware_discovery) | ADOPT_SUBSTRATE — curated skills per Task 7 |
| `strix/skills/cloud/azure.md`, `technologies/{electron_desktop_apps,llm_applications}.md`, `vulnerabilities/{agentic_system_security,argument_injection,browser_security,semantic_confusion}.md`, `custom/npx_confusion.md`, `reconnaissance/infrastructure_lifecycle.md`, `scan_modes/diff.md` + updates to existing skills | ADOPT_SUBSTRATE — curated skills |
| `strix/skills/tooling/{hurl,hypothesis}.md` | EXCLUDE_PRODUCT — sandbox image ships neither tool; files deleted post-apply and recorded in the gate's reviewed-deletion allowlist |
| `strix/interface/viewer/**` incl. Go TUI `internal/**`, frontend `src/**`, rebuilt `static/assets/**` | ADOPT_SUBSTRATE (substrate viewer); owned viewer in `lyrashield/interface/viewer/` is the product path |
| `strix/telemetry/**` | ADOPT_SUBSTRATE + re-applied `TelemetryReportState` Protocol seam (import-cycle fix; updated for `get_process_llm_usage`/`get_process_duration_seconds`) |
| `strix/config/loader.py` | ADOPT_SUBSTRATE + re-applied `register_settings_loader` composition seam |
| `strix/skills/__init__.py` | ADOPT_SUBSTRATE — fork's telemetry gate DROPPED (upstream no longer sends per-load beacons; set feeds the `end` beacon which stays behind `telemetry.enabled`) |
| Remaining `strix/**` modifications | ADOPT_SUBSTRATE; compat patches re-applied only where upstream lacks the fix (models.py, auth_cli.py, viewer files, agents_graph/tools.py, proxy tools/caido_api); `strix/skills/__init__.py` now matches upstream exactly (product telemetry gate removed); `semantic_confusion.md` carries a reviewed content edit dropping references to the excluded hurl/hypothesis skills |
| Deleted `strix/skills/tooling/{hurl,hypothesis}.md` | Reviewed deletions — recorded in the gate's `REVIEWED_DELETED` allowlist |

### Owned ports (`lyrashield/**`)

| File | Ported behavior |
|---|---|
| `lyrashield/policy/loader.py` | ce0db302 merge-persist, 3e88e498 linked model/key/base invalidation, c514f712 active-alias persistence |
| `lyrashield/lifecycle/agents.py` | 1edafd3e `resumable` flag, `_unreachable_locked`, `reachability`, send-drop for terminal non-resumable agents (ordered before the owned reactivation path), `_parent_notified` + `claim_parent_notice` |
| `lyrashield/lifecycle/execution.py` | 1edafd3e `resumable=interactive` on `attach_runtime`; non-interactive post-completion park loop removed (loops exit — sends to them are refused); `claim_parent_notice` in `_notify_parent_on_terminal` |
| `lyrashield/lifecycle/inputs.py` | 583af23d `routes_through_litellm` gate on prompt-cache args; cf179d56 `reasoning=max` via top-level `extra_body` |
| `lyrashield/policy/models.py` | `StrixProvider` `api_key`/`base_url` endpoint binding + `_CredentialedLitellmProvider` + `_create_fallback_provider` (needed by `resolve_dedupe_model`); `routes_through_litellm`; ZAI/GLM frontier family (b438632e parity) |
| `lyrashield/policy/settings.py` | `stream_idle_timeout`, `max_tool_calls_per_turn` fields (substrate `get_model` reads them through the loader seam) |
| `lyrashield/interface/viewer/server.py` | 6f88b7d7 session capability required for all run data, including the launched run |
| `lyrashield/artifacts/writer.py` | 391d81be-family calibration metadata rendering (confidence, counterevidence, confidence_rationale, severity_change_conditions, fix_verification, advisory/contextual CVSS) — render-when-present only; producer schema is Task 8 scope |
| `lyrashield/interface/main.py` | warm-up path uses `resolve_dedupe_model` (provider-bound creds) |
| `lyrashield/tools/agents_graph/tools.py` | 1edafd3e `delivery_status=not_delivered` + `target_status`, `wait_outcome=no_active_agents`, `filed_report_ids` |
| `lyrashield/tools/proxy/tools.py` | 187f41f3 `clean_optional` on list_requests/list_sitemap filters |
| `lyrashield/tools/reporting/tool.py` | 187f41f3 `clean_optional` on `_do_list_reports` filters |
| `lyrashield/interface/viewer/report_pdf.py` | 1df67c52 markdown-it-py renderer, text normalization, severity/duration guards |
| `lyrashield/artifacts/dedupe.py` | cf179d56 provider-bound dedupe credentials (`resolve_dedupe_model`) replacing colliding `extra_args` |

### Excluded paths

| Path | Reason |
|---|---|
| `skills/**` (top-level) | Not shipped by this fork (pre-existing); content markets the rejected strix cloud CLI |
| `docs/**` delta | Owned, LyraShield-branded docs tree |
| `README.md`, `CONTRIBUTING.md`, `AGENTS.md` | Owned/absent files; upstream edits not applicable |
| `scripts/install.sh`, `scripts/tui_sidecar_hook.py` | Previously removed by the fork (unreviewed installer contract) |
| `pyproject.toml`, `uv.lock` | Owned packaging; hand-ported dep (`markdown-it-py` in viewer extra) + ruff ignores, then `uv lock` |
| `.pre-commit-config.yaml` | Owned; reviewed for the upstream mypy-hook fix |
| Upstream `tests/**` the fork never carried | Keep curated test set; new tests adopted only for adopted substrate features |
| LiteLLM/GPT-6 mapping, Vercel gateway, HTTP-exchange evidence, mount-free transport, etc. | DEFER_WITH_REASON — unreleased-main items per the handoff disposition table; not in v1.6.2 |

## Open upstream PRs/issues (unreleased reference `355a8bb4`) — disposition per handoff table

All handled per the handoff "Unreleased changes and open PR disposition" table; none are in
the v1.6.2 release gap. Summary: Task 2/3/8/9/12 own the listed items; `2dadbb74`
(LiteLLM/GPT-6) and `0c4364a6` (Vercel gateway) stay out of this import entirely.

## Result

Committed as `73b44677`. Final controlled-derivative state vs v1.6.2
(`ff5c8cc8e46d8e60c2bc2439f7bcb07c05ca3db2`): 14 modified files + 2 reviewed
deletions, footprint +149/-258, patch digest
`30b8c59dc521d1fc9fceaf0d7b972c11d03a6808` — enforced by
`scripts/verify-controlled-derivative.sh`.
