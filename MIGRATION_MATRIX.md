# Strix Migration Matrix

- Target upstream: `v1.5.2` (`597aae67159636ee794a02a3cc1694138d619c44`)
- Fork HEAD: `63800d5e66a8b6cc0c767a02c10cf9faabd9d553`
- Changed `strix/` paths: 175 rows (175 unique paths), covering 12,226 insertions and 17,605 deletions relative to `v1.5.2`.

## Summary

The bulk of the drift relative to `v1.5.2` is in five areas:
1. **Product Python Textual TUI** (`strix/interface/tui/app.py`, `strix/interface/tui/renderers/`, `strix/interface/assets/tui_styles.tcss`) — must move to `lyrashield/interface/tui/`.
2. **Model/provider/cost policy** (`strix/config/**`) — move to `lyrashield/policy`.
3. **Core lifecycle, budget, and recovery** (`strix/core/**`) — move to `lyrashield/lifecycle`.
4. **Report/artifact/viewer serialization** (`strix/report/**`, `strix/interface/viewer/server.py`, `strix/interface/viewer/transcript.py`) — move to `lyrashield/artifacts`.
5. **CLI/bootstrap** (`strix/interface/main.py`, `strix/interface/cli.py`, etc.) — move to `lyrashield_adapter` or `lyrashield/lifecycle`.

The upstream **Go TUI sidecar** (`strix/interface/tui/cmd/strix-tui/`, `strix/interface/tui/backend/`, `strix/interface/tui/internal/`, etc.) and the upstream Python TUI runtime (`strix/interface/tui/live_view.py`, `strix/interface/tui/runtime.py`, `strix/interface/tui/sidecar.py`) are accepted from `v1.5.2`. The deleted upstream helpers `strix/utils/secret_files.py` and `strix/utils/api_spec.py` are also restored.

The `Upstream v1.5.2 overlap?` column means: `yes` = the path exists in both `v1.5.2` and `HEAD` and the diff must be reconciled (modified); `no` = the path is only in `HEAD` (added); `n/a` = the path is only in `v1.5.2` or is a rename source (deleted).

## Matrix

| File | Δ (add/del) | Upstream v1.5.2 overlap? | Proposed disposition | LyraShield behavior | Rationale | Status |
|------|------------:|--------------------------|----------------------|---------------------|-----------|--------|
| `strix/agents/factory.py` | +148/-121 | yes | retain as generic seam | Generic `register_agent_tools()` and agent-builder extension; product-specific redaction, programmatic calling, and model pass-through move to `lyrashield/lifecycle`/`policy`/`tools`. | v1.5.2 already has the tool registration seam; the retained patch must be a small, documented, upstream-submittable generic extension (e.g., tool wrappers, model pass-through) and not product logic. | needs-inspection |
| `strix/agents/prompt.py` | +26/-17 | yes | move to lyrashield/skills | Product agent prompt overlay: [SYSTEM-NOTICE] context handling and prompt formatting. | Product agent prompt overlay; register as a skill or override. |  |
| `strix/agents/prompts/system_prompt.jinja` | +68/-127 | yes | move to lyrashield/skills | Product system-prompt overlay with trust-boundary markers and product-specific instructions. | Product system-prompt overlay; register as extra skill or override. |  |
| `strix/config/__init__.py` | +8/-5 | yes | accept upstream v1.5.2 | Re-exports model-default helpers and removes `IntegrationSettings`; tied to product model-default reset. | Product model-default and settings-shape policy; belongs with `lyrashield/policy`. | done |
| `strix/config/codex.py` | +41/-26 | yes | move to lyrashield/policy | Auth-mode mapping (subscription vs metered) and model-name normalization. | Product cost/auth mode policy; used to set zero-cost and validate subscriptions. | done |
| `strix/config/loader.py` | +12/-5 | yes | upstream as generic seam | `register_settings_loader()` seam added; otherwise v1.5.2 loader. | Generic seam lets product loader override settings without upstream importing `lyrashield`. | done |
| `strix/config/models.py` | +275/-251 | yes | move to lyrashield/policy | GPT-5.6 model/provider helpers, provider-specific extra headers, and Azure rate pinning. | Product model/provider acceptance rules and cost safety; must be outside upstream config. | done |
| `strix/config/settings.py` | +309/-51 | yes | move to lyrashield/policy | LYRASHIELD_* env aliases, product boundary flag, ChatGPT subscription opt-out, web-search settings. | Product env/alias/boundary configuration; upstream settings should be generic. | done |
| `strix/config/tool_call_ids.py` | 0/-117 | n/a | accept upstream v1.5.2 | Restore the upstream v1.5.2 version of this file. | No product behavior to preserve; target is byte-identical v1.5.2, so the upstream file is restored. |  |
| `strix/config/tool_call_limits.py` | 0/-46 | n/a | accept upstream v1.5.2 | Restore the upstream v1.5.2 version of this file. | No product behavior to preserve; target is byte-identical v1.5.2, so the upstream file is restored. |  |
| `strix/core/agents.py` | +205/-66 | yes | move to lyrashield/lifecycle | Trust-boundary markers, [SYSTEM-NOTICE] wrappers, peer-message anti-spoofing. | Product agent message trust boundaries and anti-spoofing. |  |
| `strix/core/execution.py` | +179/-76 | yes | move to lyrashield/lifecycle | ProviderRefusalError, transient mid-stream retry, structured refusals. | Product execution error/recovery policy. |  |
| `strix/core/hooks.py` | +565/-35 | yes | move to lyrashield/lifecycle | Budget hooks, cost upper bounds, out-of-band reservations, token/agent caps, GPT-5.6 rate card. | Product budget enforcement and lifecycle hooks; needs a narrow factory seam for runner usage. |  |
| `strix/core/inputs.py` | +171/-101 | yes | move to lyrashield/lifecycle | Redaction of target inputs, token/budget cap validation, max-budget enforcement. | Product input sanitization and budget gating. |  |
| `strix/core/runner.py` | +360/-82 | yes | move to lyrashield/lifecycle | Delegate fallback, content-filter recovery, partial-finding salvage, usage hooks integration. | Product runner lifecycle; requires report-state and usage-hooks factories to avoid copying runner. |  |
| `strix/core/sessions.py` | +160/-38 | yes | move to lyrashield/lifecycle | Server-conversation session, redaction of outputs, prompt-cache/extra-headers. | Product session handling and privacy controls. |  |
| `strix/interface/assets/tui_styles.tcss` | +697/-0 | no | move to lyrashield/interface/tui/ | CSS for the product Textual TUI. | Part of the product Python Textual TUI. |  |
| `strix/interface/auth_cli.py` | +12/-2 | yes | move to lyrashield_adapter | ChatGPT subscription rejection at product boundary. | Product auth CLI gate. |  |
| `strix/interface/cli.py` | +89/-52 | yes | move to lyrashield/lifecycle | Non-interactive execution path, safe failure labels, warm-up usage recording. | Product CLI lifecycle behavior (non-interactive, safe output). |  |
| `strix/interface/cli_args.py` | 0/-380 | n/a | accept upstream v1.5.2 | Restore the upstream v1.5.2 version of this file. | No product behavior to preserve; target is byte-identical v1.5.2, so the upstream file is restored. |  |
| `strix/interface/environment.py` | 0/-217 | n/a | accept upstream v1.5.2 | Restore the upstream v1.5.2 version of this file. | No product behavior to preserve; target is byte-identical v1.5.2, so the upstream file is restored. |  |
| `strix/interface/interactive.py` | 0/-38 | n/a | accept upstream v1.5.2 | Restore the upstream v1.5.2 version of this file. | No product behavior to preserve; target is byte-identical v1.5.2, so the upstream file is restored. |  |
| `strix/interface/main.py` | +1007/-144 | yes | move to lyrashield_adapter | Product CLI orchestration: version, `--update` disabled, `provider-contract` subcommand, target/run hardening, telemetry args. | Main composition root; product-specific dispatch and gates move to adapter, leaving a generic `main()` that consumes registered subcommands/hooks. |  |
| `strix/interface/provider_contract_cli.py` | +76/-0 | no | move to lyrashield_adapter | `provider-contract` subcommand parser and runner. | Product CLI subcommand; dispatches to `lyrashield/policy` probe. |  |
| `strix/interface/scan_setup.py` | 0/-265 | n/a | accept upstream v1.5.2 | Restore the upstream v1.5.2 version of this file. | No product behavior to preserve; target is byte-identical v1.5.2, so the upstream file is restored. |  |
| `strix/interface/tui/__init__.py` | +3/-3 | yes | accept upstream v1.5.2 | Restore upstream `TuiLiveView` export; the product Textual TUI lives in `lyrashield/interface/tui/`. | Upstream `__init__.py` exports the live-view module for the Go/Bubble Tea sidecar. |  |
| `strix/interface/tui/app.py` | +2090/-0 | no | move to lyrashield/interface/tui/ | Python Textual TUI application (`StrixTUIApp`, `run_tui()`, lifecycle hooks, warm-up usage recording). | Product-specific Python Textual TUI; upstream strix should keep the Go/Bubble Tea sidecar. |  |
| `strix/interface/tui/backend/__init__.py` | 0/-7 | n/a | accept upstream v1.5.2 | Restore the upstream v1.5.2 version of this file. | No product behavior to preserve; target is byte-identical v1.5.2, so the upstream file is restored. |  |
| `strix/interface/tui/backend/controller.py` | 0/-488 | n/a | accept upstream v1.5.2 | Restore the upstream v1.5.2 version of this file. | No product behavior to preserve; target is byte-identical v1.5.2, so the upstream file is restored. |  |
| `strix/interface/tui/backend/live_view.py` | 0/-136 | n/a | accept upstream v1.5.2 | Restore the upstream v1.5.2 version of this file. | No product behavior to preserve; target is byte-identical v1.5.2, so the upstream file is restored. |  |
| `strix/interface/tui/backend/messages.py` | 0/-61 | n/a | accept upstream v1.5.2 | Restore the upstream v1.5.2 version of this file. | No product behavior to preserve; target is byte-identical v1.5.2, so the upstream file is restored. |  |
| `strix/interface/tui/backend/projection.py` | 0/-182 | n/a | accept upstream v1.5.2 | Restore the upstream v1.5.2 version of this file. | No product behavior to preserve; target is byte-identical v1.5.2, so the upstream file is restored. |  |
| `strix/interface/tui/backend/protocol.py` | 0/-40 | n/a | accept upstream v1.5.2 | Restore the upstream v1.5.2 version of this file. | No product behavior to preserve; target is byte-identical v1.5.2, so the upstream file is restored. |  |
| `strix/interface/tui/backend/server.py` | 0/-531 | n/a | accept upstream v1.5.2 | Restore the upstream v1.5.2 version of this file. | No product behavior to preserve; target is byte-identical v1.5.2, so the upstream file is restored. |  |
| `strix/interface/tui/cmd/strix-tui/main.go` | 0/-35 | n/a | accept upstream v1.5.2 | Restore the upstream v1.5.2 version of this file. | No product behavior to preserve; target is byte-identical v1.5.2, so the upstream file is restored. |  |
| `strix/interface/tui/go.mod` | 0/-32 | n/a | accept upstream v1.5.2 | Restore the upstream v1.5.2 version of this file. | No product behavior to preserve; target is byte-identical v1.5.2, so the upstream file is restored. |  |
| `strix/interface/tui/go.sum` | 0/-61 | n/a | accept upstream v1.5.2 | Restore the upstream v1.5.2 version of this file. | No product behavior to preserve; target is byte-identical v1.5.2, so the upstream file is restored. |  |
| `strix/interface/tui/internal/app/agents.go` | 0/-253 | n/a | accept upstream v1.5.2 | Restore the upstream v1.5.2 version of this file. | No product behavior to preserve; target is byte-identical v1.5.2, so the upstream file is restored. |  |
| `strix/interface/tui/internal/app/client.go` | 0/-250 | n/a | accept upstream v1.5.2 | Restore the upstream v1.5.2 version of this file. | No product behavior to preserve; target is byte-identical v1.5.2, so the upstream file is restored. |  |
| `strix/interface/tui/internal/app/client_test.go` | 0/-284 | n/a | accept upstream v1.5.2 | Restore the upstream v1.5.2 version of this file. | No product behavior to preserve; target is byte-identical v1.5.2, so the upstream file is restored. |  |
| `strix/interface/tui/internal/app/findings_test.go` | 0/-299 | n/a | accept upstream v1.5.2 | Restore the upstream v1.5.2 version of this file. | No product behavior to preserve; target is byte-identical v1.5.2, so the upstream file is restored. |  |
| `strix/interface/tui/internal/app/frame_bench_test.go` | 0/-98 | n/a | accept upstream v1.5.2 | Restore the upstream v1.5.2 version of this file. | No product behavior to preserve; target is byte-identical v1.5.2, so the upstream file is restored. |  |
| `strix/interface/tui/internal/app/input_test.go` | 0/-216 | n/a | accept upstream v1.5.2 | Restore the upstream v1.5.2 version of this file. | No product behavior to preserve; target is byte-identical v1.5.2, so the upstream file is restored. |  |
| `strix/interface/tui/internal/app/model.go` | 0/-410 | n/a | accept upstream v1.5.2 | Restore the upstream v1.5.2 version of this file. | No product behavior to preserve; target is byte-identical v1.5.2, so the upstream file is restored. |  |
| `strix/interface/tui/internal/app/model_test.go` | 0/-1289 | n/a | accept upstream v1.5.2 | Restore the upstream v1.5.2 version of this file. | No product behavior to preserve; target is byte-identical v1.5.2, so the upstream file is restored. |  |
| `strix/interface/tui/internal/app/selection.go` | 0/-284 | n/a | accept upstream v1.5.2 | Restore the upstream v1.5.2 version of this file. | No product behavior to preserve; target is byte-identical v1.5.2, so the upstream file is restored. |  |
| `strix/interface/tui/internal/app/selection_test.go` | 0/-185 | n/a | accept upstream v1.5.2 | Restore the upstream v1.5.2 version of this file. | No product behavior to preserve; target is byte-identical v1.5.2, so the upstream file is restored. |  |
| `strix/interface/tui/internal/app/setup.go` | 0/-522 | n/a | accept upstream v1.5.2 | Restore the upstream v1.5.2 version of this file. | No product behavior to preserve; target is byte-identical v1.5.2, so the upstream file is restored. |  |
| `strix/interface/tui/internal/app/setup_log_test.go` | 0/-117 | n/a | accept upstream v1.5.2 | Restore the upstream v1.5.2 version of this file. | No product behavior to preserve; target is byte-identical v1.5.2, so the upstream file is restored. |  |
| `strix/interface/tui/internal/app/setup_prompt_test.go` | 0/-387 | n/a | accept upstream v1.5.2 | Restore the upstream v1.5.2 version of this file. | No product behavior to preserve; target is byte-identical v1.5.2, so the upstream file is restored. |  |
| `strix/interface/tui/internal/app/update.go` | 0/-670 | n/a | accept upstream v1.5.2 | Restore the upstream v1.5.2 version of this file. | No product behavior to preserve; target is byte-identical v1.5.2, so the upstream file is restored. |  |
| `strix/interface/tui/internal/app/view.go` | 0/-841 | n/a | accept upstream v1.5.2 | Restore the upstream v1.5.2 version of this file. | No product behavior to preserve; target is byte-identical v1.5.2, so the upstream file is restored. |  |
| `strix/interface/tui/internal/app/vuln_report.go` | 0/-178 | n/a | accept upstream v1.5.2 | Restore the upstream v1.5.2 version of this file. | No product behavior to preserve; target is byte-identical v1.5.2, so the upstream file is restored. |  |
| `strix/interface/tui/internal/app/vulnerabilities.go` | 0/-543 | n/a | accept upstream v1.5.2 | Restore the upstream v1.5.2 version of this file. | No product behavior to preserve; target is byte-identical v1.5.2, so the upstream file is restored. |  |
| `strix/interface/tui/internal/app/wire.go` | 0/-467 | n/a | accept upstream v1.5.2 | Restore the upstream v1.5.2 version of this file. | No product behavior to preserve; target is byte-identical v1.5.2, so the upstream file is restored. |  |
| `strix/interface/tui/internal/protocol/protocol.go` | 0/-118 | n/a | accept upstream v1.5.2 | Restore the upstream v1.5.2 version of this file. | No product behavior to preserve; target is byte-identical v1.5.2, so the upstream file is restored. |  |
| `strix/interface/tui/internal/protocol/protocol_test.go` | 0/-22 | n/a | accept upstream v1.5.2 | Restore the upstream v1.5.2 version of this file. | No product behavior to preserve; target is byte-identical v1.5.2, so the upstream file is restored. |  |
| `strix/interface/tui/internal/render/agent_message.go` | 0/-320 | n/a | accept upstream v1.5.2 | Restore the upstream v1.5.2 version of this file. | No product behavior to preserve; target is byte-identical v1.5.2, so the upstream file is restored. |  |
| `strix/interface/tui/internal/render/agents_graph.go` | 0/-86 | n/a | accept upstream v1.5.2 | Restore the upstream v1.5.2 version of this file. | No product behavior to preserve; target is byte-identical v1.5.2, so the upstream file is restored. |  |
| `strix/interface/tui/internal/render/chat.go` | 0/-32 | n/a | accept upstream v1.5.2 | Restore the upstream v1.5.2 version of this file. | No product behavior to preserve; target is byte-identical v1.5.2, so the upstream file is restored. |  |
| `strix/interface/tui/internal/render/code.go` | 0/-70 | n/a | accept upstream v1.5.2 | Restore the upstream v1.5.2 version of this file. | No product behavior to preserve; target is byte-identical v1.5.2, so the upstream file is restored. |  |
| `strix/interface/tui/internal/render/dependency.go` | 0/-105 | n/a | accept upstream v1.5.2 | Restore the upstream v1.5.2 version of this file. | No product behavior to preserve; target is byte-identical v1.5.2, so the upstream file is restored. |  |
| `strix/interface/tui/internal/render/file_edit.go` | 0/-143 | n/a | accept upstream v1.5.2 | Restore the upstream v1.5.2 version of this file. | No product behavior to preserve; target is byte-identical v1.5.2, so the upstream file is restored. |  |
| `strix/interface/tui/internal/render/helpers.go` | 0/-112 | n/a | accept upstream v1.5.2 | Restore the upstream v1.5.2 version of this file. | No product behavior to preserve; target is byte-identical v1.5.2, so the upstream file is restored. |  |
| `strix/interface/tui/internal/render/image.go` | 0/-106 | n/a | accept upstream v1.5.2 | Restore the upstream v1.5.2 version of this file. | No product behavior to preserve; target is byte-identical v1.5.2, so the upstream file is restored. |  |
| `strix/interface/tui/internal/render/image_detect.go` | 0/-139 | n/a | accept upstream v1.5.2 | Restore the upstream v1.5.2 version of this file. | No product behavior to preserve; target is byte-identical v1.5.2, so the upstream file is restored. |  |
| `strix/interface/tui/internal/render/image_detect_test.go` | 0/-133 | n/a | accept upstream v1.5.2 | Restore the upstream v1.5.2 version of this file. | No product behavior to preserve; target is byte-identical v1.5.2, so the upstream file is restored. |  |
| `strix/interface/tui/internal/render/image_detect_unix.go` | 0/-37 | n/a | accept upstream v1.5.2 | Restore the upstream v1.5.2 version of this file. | No product behavior to preserve; target is byte-identical v1.5.2, so the upstream file is restored. |  |
| `strix/interface/tui/internal/render/image_detect_windows.go` | 0/-19 | n/a | accept upstream v1.5.2 | Restore the upstream v1.5.2 version of this file. | No product behavior to preserve; target is byte-identical v1.5.2, so the upstream file is restored. |  |
| `strix/interface/tui/internal/render/image_kitty.go` | 0/-202 | n/a | accept upstream v1.5.2 | Restore the upstream v1.5.2 version of this file. | No product behavior to preserve; target is byte-identical v1.5.2, so the upstream file is restored. |  |
| `strix/interface/tui/internal/render/image_kitty_test.go` | 0/-103 | n/a | accept upstream v1.5.2 | Restore the upstream v1.5.2 version of this file. | No product behavior to preserve; target is byte-identical v1.5.2, so the upstream file is restored. |  |
| `strix/interface/tui/internal/render/markdown_test.go` | 0/-103 | n/a | accept upstream v1.5.2 | Restore the upstream v1.5.2 version of this file. | No product behavior to preserve; target is byte-identical v1.5.2, so the upstream file is restored. |  |
| `strix/interface/tui/internal/render/notes.go` | 0/-111 | n/a | accept upstream v1.5.2 | Restore the upstream v1.5.2 version of this file. | No product behavior to preserve; target is byte-identical v1.5.2, so the upstream file is restored. |  |
| `strix/interface/tui/internal/render/proxy.go` | 0/-577 | n/a | accept upstream v1.5.2 | Restore the upstream v1.5.2 version of this file. | No product behavior to preserve; target is byte-identical v1.5.2, so the upstream file is restored. |  |
| `strix/interface/tui/internal/render/registry.go` | 0/-135 | n/a | accept upstream v1.5.2 | Restore the upstream v1.5.2 version of this file. | No product behavior to preserve; target is byte-identical v1.5.2, so the upstream file is restored. |  |
| `strix/interface/tui/internal/render/render_test.go` | 0/-251 | n/a | accept upstream v1.5.2 | Restore the upstream v1.5.2 version of this file. | No product behavior to preserve; target is byte-identical v1.5.2, so the upstream file is restored. |  |
| `strix/interface/tui/internal/render/report.go` | 0/-126 | n/a | accept upstream v1.5.2 | Restore the upstream v1.5.2 version of this file. | No product behavior to preserve; target is byte-identical v1.5.2, so the upstream file is restored. |  |
| `strix/interface/tui/internal/render/report_list.go` | 0/-129 | n/a | accept upstream v1.5.2 | Restore the upstream v1.5.2 version of this file. | No product behavior to preserve; target is byte-identical v1.5.2, so the upstream file is restored. |  |
| `strix/interface/tui/internal/render/respond.go` | 0/-18 | n/a | accept upstream v1.5.2 | Restore the upstream v1.5.2 version of this file. | No product behavior to preserve; target is byte-identical v1.5.2, so the upstream file is restored. |  |
| `strix/interface/tui/internal/render/scan.go` | 0/-31 | n/a | accept upstream v1.5.2 | Restore the upstream v1.5.2 version of this file. | No product behavior to preserve; target is byte-identical v1.5.2, so the upstream file is restored. |  |
| `strix/interface/tui/internal/render/simple.go` | 0/-52 | n/a | accept upstream v1.5.2 | Restore the upstream v1.5.2 version of this file. | No product behavior to preserve; target is byte-identical v1.5.2, so the upstream file is restored. |  |
| `strix/interface/tui/internal/render/styles.go` | 0/-82 | n/a | accept upstream v1.5.2 | Restore the upstream v1.5.2 version of this file. | No product behavior to preserve; target is byte-identical v1.5.2, so the upstream file is restored. |  |
| `strix/interface/tui/internal/render/terminal.go` | 0/-183 | n/a | accept upstream v1.5.2 | Restore the upstream v1.5.2 version of this file. | No product behavior to preserve; target is byte-identical v1.5.2, so the upstream file is restored. |  |
| `strix/interface/tui/internal/render/todo.go` | 0/-80 | n/a | accept upstream v1.5.2 | Restore the upstream v1.5.2 version of this file. | No product behavior to preserve; target is byte-identical v1.5.2, so the upstream file is restored. |  |
| `strix/interface/tui/live_view.py` | +12/-152 | yes | accept upstream v1.5.2 | Product Textual TUI (moved out) consumes the upstream `TuiLiveView`; verify API compatibility after the app is relocated. | v1.5.2 `TuiLiveView` is the upstream live transcript/state manager; the fork's stripped-down version was an adaptation for the product app. | needs-inspection |
| `strix/interface/tui/messages.py` | +43/-0 | no | move to lyrashield/interface/tui/ | Async message bridge from TUI input to SDK-backed agents. | Product-specific TUI helper used by `app.py`. |  |
| `strix/interface/tui/renderers/__init__.py` | +33/-0 | no | move to lyrashield/interface/tui/ | Product Python Textual TUI source. | Product TUI replaces the Go sidecar; upstream strix keeps the Go/Bubble Tea TUI. |  |
| `strix/interface/tui/renderers/agent_message_renderer.py` | +180/-0 | no | move to lyrashield/interface/tui/ | Product Python Textual TUI source. | Product TUI replaces the Go sidecar; upstream strix keeps the Go/Bubble Tea TUI. |  |
| `strix/interface/tui/renderers/agents_graph_renderer.py` | +175/-0 | no | move to lyrashield/interface/tui/ | Product Python Textual TUI source. | Product TUI replaces the Go sidecar; upstream strix keeps the Go/Bubble Tea TUI. |  |
| `strix/interface/tui/renderers/base_renderer.py` | +30/-0 | no | move to lyrashield/interface/tui/ | Product Python Textual TUI source. | Product TUI replaces the Go sidecar; upstream strix keeps the Go/Bubble Tea TUI. |  |
| `strix/interface/tui/renderers/filesystem_renderer.py` | +266/-0 | no | move to lyrashield/interface/tui/ | Product Python Textual TUI source. | Product TUI replaces the Go sidecar; upstream strix keeps the Go/Bubble Tea TUI. |  |
| `strix/interface/tui/renderers/finish_renderer.py` | +65/-0 | no | move to lyrashield/interface/tui/ | Product Python Textual TUI source. | Product TUI replaces the Go sidecar; upstream strix keeps the Go/Bubble Tea TUI. |  |
| `strix/interface/tui/renderers/load_skill_renderer.py` | +37/-0 | no | move to lyrashield/interface/tui/ | Product Python Textual TUI source. | Product TUI replaces the Go sidecar; upstream strix keeps the Go/Bubble Tea TUI. |  |
| `strix/interface/tui/renderers/notes_renderer.py` | +180/-0 | no | move to lyrashield/interface/tui/ | Product Python Textual TUI source. | Product TUI replaces the Go sidecar; upstream strix keeps the Go/Bubble Tea TUI. |  |
| `strix/interface/tui/renderers/proxy_renderer.py` | +536/-0 | no | move to lyrashield/interface/tui/ | Product Python Textual TUI source. | Product TUI replaces the Go sidecar; upstream strix keeps the Go/Bubble Tea TUI. |  |
| `strix/interface/tui/renderers/registry.py` | +71/-0 | no | move to lyrashield/interface/tui/ | Product Python Textual TUI source. | Product TUI replaces the Go sidecar; upstream strix keeps the Go/Bubble Tea TUI. |  |
| `strix/interface/tui/renderers/reporting_renderer.py` | +547/-0 | no | move to lyrashield/interface/tui/ | Product Python Textual TUI source. | Product TUI replaces the Go sidecar; upstream strix keeps the Go/Bubble Tea TUI. |  |
| `strix/interface/tui/renderers/respond_renderer.py` | +35/-0 | no | move to lyrashield/interface/tui/ | Product Python Textual TUI source. | Product TUI replaces the Go sidecar; upstream strix keeps the Go/Bubble Tea TUI. |  |
| `strix/interface/tui/renderers/shell_renderer.py` | +266/-0 | no | move to lyrashield/interface/tui/ | Product Python Textual TUI source. | Product TUI replaces the Go sidecar; upstream strix keeps the Go/Bubble Tea TUI. |  |
| `strix/interface/tui/renderers/thinking_renderer.py` | +31/-0 | no | move to lyrashield/interface/tui/ | Product Python Textual TUI source. | Product TUI replaces the Go sidecar; upstream strix keeps the Go/Bubble Tea TUI. |  |
| `strix/interface/tui/renderers/todo_renderer.py` | +225/-0 | no | move to lyrashield/interface/tui/ | Product Python Textual TUI source. | Product TUI replaces the Go sidecar; upstream strix keeps the Go/Bubble Tea TUI. |  |
| `strix/interface/tui/renderers/user_message_renderer.py` | +29/-0 | no | move to lyrashield/interface/tui/ | Product Python Textual TUI source. | Product TUI replaces the Go sidecar; upstream strix keeps the Go/Bubble Tea TUI. |  |
| `strix/interface/tui/renderers/web_search_renderer.py` | +59/-0 | no | move to lyrashield/interface/tui/ | Product Python Textual TUI source. | Product TUI replaces the Go sidecar; upstream strix keeps the Go/Bubble Tea TUI. |  |
| `strix/interface/tui/runtime.py` | 0/-392 | n/a | accept upstream v1.5.2 | Restore the upstream v1.5.2 version of this file. | No product behavior to preserve; target is byte-identical v1.5.2, so the upstream file is restored. |  |
| `strix/interface/tui/sidecar.py` | 0/-191 | n/a | accept upstream v1.5.2 | Restore the upstream v1.5.2 version of this file. | No product behavior to preserve; target is byte-identical v1.5.2, so the upstream file is restored. |  |
| `strix/interface/update_check.py` | +28/-23 | yes | accept upstream v1.5.2 | Revert attribution banner and product-boundary gate; product disables self-update at the adapter. | Self-update disabling belongs in `lyrashield_adapter` env; revert to upstream update check. |  |
| `strix/interface/utils.py` | +274/-277 | yes | move to lyrashield/artifacts | Safe repo-name validation, shell=False subprocess boundary, git `--` terminator. | Product safety helpers for CLI and runtime; reused by adapter and tools. |  |
| `strix/interface/viewer/auth.py` | +11/-5 | yes | accept upstream v1.5.2 | Restore use of `strix.utils.secret_files.write_secret_text` once `secret_files.py` is accepted from v1.5.2. | The fork inlined secret writing because it deleted `secret_files.py`; restoring the helper returns to v1.5.2. Verify the moved product viewer does not require the non-context-manager request style. | needs-inspection |
| `strix/interface/viewer/cli.py` | +11/-0 | yes | accept upstream v1.5.2 | Revert attribution banner added by the fork. | No product behavior; target is v1.5.2. |  |
| `strix/interface/viewer/frontend/src/components/live/tool-renderers/ViewImageRenderer.tsx` | +6/-29 | yes | move to lyrashield/interface/viewer/ | Product viewer hardening: disable inline image rendering and surface load errors only. | Product privacy/bandwidth decision for the live tool renderer; strix viewer reverts to v1.5.2. |  |
| `strix/interface/viewer/frontend/src/components/vulnerability/MdCodeBlock.tsx` | +3/-3 | yes | upstream as generic fix | Tailwind class value fixes for code block rendering. | Generic viewer UI style fix; suitable for upstream PR after removing product attribution if any. | deferred |
| `strix/interface/viewer/server.py` | +22/-5 | yes | move to lyrashield/artifacts | Product viewer server hardening (host/port/auth bounding). | Product viewer/report serving and worker artifact contract. |  |
| `strix/interface/viewer/static/assets/index-C3kQ5kk8.css` | +10/-0 | no | delete | Remove this fork-added file from `strix/`; no product behavior to preserve. | Build artifact or product addition not needed in the upstream tree; product may rebuild in `lyrashield/`. |  |
| `strix/interface/viewer/static/assets/index-DBJ-RJqo.js` | 0/-6 | n/a | accept upstream v1.5.2 | Restore the upstream v1.5.2 version of this file. | No product behavior to preserve; target is byte-identical v1.5.2, so the upstream file is restored. |  |
| `strix/interface/viewer/static/assets/index-CGvQq6oe.js` | +6/0 | no | delete | Remove this fork-added file from `strix/`; no product behavior to preserve. | Build artifact or product addition not needed in the upstream tree; product may rebuild in `lyrashield/`. |  |
| `strix/interface/viewer/static/assets/index-DKbLYAbP.css` | 0/-10 | n/a | accept upstream v1.5.2 | Restore the upstream v1.5.2 version of this file. | No product behavior to preserve; target is byte-identical v1.5.2, so the upstream file is restored. |  |
| `strix/interface/viewer/static/index.html` | +2/-2 | yes | accept upstream v1.5.2 | Revert to the upstream v1.5.2 version of this file. | No product behavior to preserve; target is byte-identical v1.5.2, so the upstream file is accepted. |  |
| `strix/interface/viewer/transcript.py` | +22/-12 | yes | move to lyrashield/artifacts | Viewer transcript redaction/bounding. | Product viewer artifact redaction. |  |
| `strix/llm/compaction.py` | +74/-32 | yes | move to lyrashield/lifecycle | Redact before summarization, compaction privacy helpers. | Product context-compaction privacy policy. |  |
| `strix/provider_contract.py` | +200/-0 | no | move to lyrashield/policy | New provider-contract probe logic and helpers. | LyraShield-only `provider-contract` diagnostic; belongs in product policy, called from adapter. | done |
| `strix/report/dedupe.py` | +343/-61 | yes | move to lyrashield/artifacts | DedupeJudgement schema, bounded payload, dynamic identity pre-check. | Product deduplication judgement and safety bounds. |  |
| `strix/report/sarif.py` | +14/-10 | yes | move to lyrashield/artifacts | SARIF generation adjustments. | Product SARIF/report artifact handling. |  |
| `strix/report/state.py` | +222/-88 | yes | move to lyrashield/artifacts | run.json schema, terminal reasons, reservations, redaction, atomic writes, schema_version. | Product artifact serialization and report-state; needs a factory seam so CLI/TUI use it. |  |
| `strix/report/usage.py` | +132/-31 | yes | move to lyrashield/artifacts | LLMUsageLedger zero-cost, cost logic, cached token handling. | Product usage accounting and cost ledger. |  |
| `strix/report/writer.py` | +9/-7 | yes | move to lyrashield/artifacts | Redaction of report output, fenced-code handling fixes. | Product report writer privacy and fence safety. |  |
| `strix/runtime/backends.py` | +13/-25 | yes | accept upstream v1.5.2 | Use upstream `register_backend()` with `supports_bind_mounts` flag. | v1.5.2 already has the runtime backend registration seam; product local-dir staging can use it. |  |
| `strix/runtime/caido_bootstrap.py` | +9/-2 | yes | move to lyrashield/runtime | Caido bootstrap correctness. | Product Caido/sandbox bootstrap. |  |
| `strix/runtime/docker_client.py` | +110/-47 | yes | move to lyrashield/runtime | Docker client product-side validation/cleanup. | Product Docker runtime hardening. |  |
| `strix/runtime/local_dir_staging.py` | +120/-0 | no | move to lyrashield/runtime | Local directory staging for sandbox runtimes. | Product runtime staging helper; register via `register_backend()` or consume from product session manager. |  |
| `strix/runtime/session_manager.py` | +162/-122 | yes | move to lyrashield/runtime | Local staging removal, bind-mount handling, session cleanup. | Product sandbox session/runtime policy. |  |
| `strix/runtime/status.py` | 0/-8 | n/a | accept upstream v1.5.2 | Restore the upstream v1.5.2 version of this file. | No product behavior to preserve; target is byte-identical v1.5.2, so the upstream file is restored. |  |
| `strix/skills/README.md` | +1/-1 | yes | accept upstream v1.5.2 | Revert to the upstream v1.5.2 version of this file. | No product behavior to preserve; target is byte-identical v1.5.2, so the upstream file is accepted. |  |
| `strix/skills/__init__.py` | +13/-71 | yes | accept upstream v1.5.2 | Use upstream `register_skill_dir()` skill registry; product overlays register `lyrashield/skills/`. | v1.5.2 already supports external skill directories and precedence shadowing; product code that relied on the fork's simplified `get_available_skills()` shape must adapt to the upstream return type (list of dicts with descriptions). |  |
| `strix/skills/cloud/gcp.md` | +1/-1 | yes | move to lyrashield/skills | Product skill overlay that references the product `firebase_firestore` skill. | References the product skill rename; keep in product skills tree. |  |
| `strix/skills/coordination/root_agent.md` | +5/-2 | yes | move to lyrashield/skills | Product skill overlay; register via `strix.skills.register_skill_dir()` so it shadows upstream. | Skill markdown is a natural overlay; no strix Python dependencies; upstream file reverts to v1.5.2. |  |
| `strix/skills/custom/api_spec_testing.md` | 0/-61 | n/a | accept upstream v1.5.2 | Restore the upstream v1.5.2 version of this file. | No product behavior to preserve; target is byte-identical v1.5.2, so the upstream file is restored. |  |
| `strix/skills/custom/dependency_cve_scanning.md` | +13/-128 | yes | move to lyrashield/skills | Product skill overlay; register via `strix.skills.register_skill_dir()` so it shadows upstream. | Skill markdown is a natural overlay; no strix Python dependencies; upstream file reverts to v1.5.2. |  |
| `strix/skills/custom/source_aware_sast.md` | +25/-13 | yes | move to lyrashield/skills | Product skill overlay; register via `strix.skills.register_skill_dir()` so it shadows upstream. | Skill markdown is a natural overlay; no strix Python dependencies; upstream file reverts to v1.5.2. |  |
| `strix/skills/frameworks/fastapi.md` | +2/-2 | yes | accept upstream v1.5.2 | Revert to the upstream v1.5.2 version of this file. | No product behavior to preserve; target is byte-identical v1.5.2, so the upstream file is accepted. |  |
| `strix/skills/scan_modes/deep.md` | +4/-4 | yes | move to lyrashield/skills | Product skill overlay; register via `strix.skills.register_skill_dir()` so it shadows upstream. | Skill markdown is a natural overlay; no strix Python dependencies; upstream file reverts to v1.5.2. |  |
| `strix/skills/technologies/active_directory.md` | +1/-1 | yes | move to lyrashield/skills | Product skill overlay; register via `strix.skills.register_skill_dir()` so it shadows upstream. | Skill markdown is a natural overlay; no strix Python dependencies; upstream file reverts to v1.5.2. |  |
| `strix/skills/technologies/firebase.md` | 0/-63 | n/a | accept upstream v1.5.2 | Restore the upstream v1.5.2 version of this file. | No product behavior to preserve; target is byte-identical v1.5.2, so the upstream file is restored. |  |
| `strix/skills/technologies/firebase_firestore.md` | +11/0 | no | move to lyrashield/skills | Product skill overlay for the renamed/extended Firebase/Firestore skill. | Product renamed the upstream `firebase.md` skill; the product version lives in `lyrashield/skills/technologies/`. |  |
| `strix/skills/tooling/ffuf.md` | +1/-2 | yes | move to lyrashield/skills | Product skill overlay; register via `strix.skills.register_skill_dir()` so it shadows upstream. | Skill markdown is a natural overlay; no strix Python dependencies; upstream file reverts to v1.5.2. |  |
| `strix/skills/tooling/httpx.md` | +1/-2 | yes | move to lyrashield/skills | Product skill overlay; register via `strix.skills.register_skill_dir()` so it shadows upstream. | Skill markdown is a natural overlay; no strix Python dependencies; upstream file reverts to v1.5.2. |  |
| `strix/skills/tooling/katana.md` | +1/-2 | yes | move to lyrashield/skills | Product skill overlay; register via `strix.skills.register_skill_dir()` so it shadows upstream. | Skill markdown is a natural overlay; no strix Python dependencies; upstream file reverts to v1.5.2. |  |
| `strix/skills/tooling/naabu.md` | +1/-2 | yes | move to lyrashield/skills | Product skill overlay; register via `strix.skills.register_skill_dir()` so it shadows upstream. | Skill markdown is a natural overlay; no strix Python dependencies; upstream file reverts to v1.5.2. |  |
| `strix/skills/tooling/nmap.md` | +1/-2 | yes | move to lyrashield/skills | Product skill overlay; register via `strix.skills.register_skill_dir()` so it shadows upstream. | Skill markdown is a natural overlay; no strix Python dependencies; upstream file reverts to v1.5.2. |  |
| `strix/skills/tooling/nuclei.md` | +1/-2 | yes | move to lyrashield/skills | Product skill overlay; register via `strix.skills.register_skill_dir()` so it shadows upstream. | Skill markdown is a natural overlay; no strix Python dependencies; upstream file reverts to v1.5.2. |  |
| `strix/skills/tooling/python.md` | +1/-1 | yes | move to lyrashield/skills | Product skill overlay; register via `strix.skills.register_skill_dir()` so it shadows upstream. | Skill markdown is a natural overlay; no strix Python dependencies; upstream file reverts to v1.5.2. |  |
| `strix/skills/tooling/semgrep.md` | +1/-2 | yes | move to lyrashield/skills | Product skill overlay; register via `strix.skills.register_skill_dir()` so it shadows upstream. | Skill markdown is a natural overlay; no strix Python dependencies; upstream file reverts to v1.5.2. |  |
| `strix/skills/tooling/sqlmap.md` | +1/-2 | yes | move to lyrashield/skills | Product skill overlay; register via `strix.skills.register_skill_dir()` so it shadows upstream. | Skill markdown is a natural overlay; no strix Python dependencies; upstream file reverts to v1.5.2. |  |
| `strix/skills/tooling/subfinder.md` | +1/-2 | yes | move to lyrashield/skills | Product skill overlay; register via `strix.skills.register_skill_dir()` so it shadows upstream. | Skill markdown is a natural overlay; no strix Python dependencies; upstream file reverts to v1.5.2. |  |
| `strix/skills/vulnerabilities/information_disclosure.md` | +4/-8 | yes | move to lyrashield/skills | Product skill overlay; register via `strix.skills.register_skill_dir()` so it shadows upstream. | Skill markdown is a natural overlay; no strix Python dependencies; upstream file reverts to v1.5.2. |  |
| `strix/skills/vulnerabilities/insecure_deserialization.md` | +5/-1 | yes | accept upstream v1.5.2 | Revert to the upstream v1.5.2 version of this file. | No product behavior to preserve; target is byte-identical v1.5.2, so the upstream file is accepted. |  |
| `strix/skills/vulnerabilities/prototype_pollution.md` | +2/-2 | yes | move to lyrashield/skills | Product skill overlay; register via `strix.skills.register_skill_dir()` so it shadows upstream. | Skill markdown is a natural overlay; no strix Python dependencies; upstream file reverts to v1.5.2. |  |
| `strix/skills/vulnerabilities/subdomain_takeover.md` | +1/-1 | yes | move to lyrashield/skills | Product skill overlay; register via `strix.skills.register_skill_dir()` so it shadows upstream. | Skill markdown is a natural overlay; no strix Python dependencies; upstream file reverts to v1.5.2. |  |
| `strix/telemetry/README.md` | +15/-22 | yes | accept upstream v1.5.2 | Revert to the upstream v1.5.2 version of this file. | No product behavior to preserve; target is byte-identical v1.5.2, so the upstream file is accepted. |  |
| `strix/telemetry/__init__.py` | +8/-0 | yes | accept upstream v1.5.2 | Revert to the upstream v1.5.2 version of this file. | No product behavior to preserve; target is byte-identical v1.5.2, so the upstream file is accepted. |  |
| `strix/telemetry/_common.py` | +23/-13 | yes | accept upstream v1.5.2 | Revert to the upstream v1.5.2 version of this file. | No product behavior to preserve; target is byte-identical v1.5.2, so the upstream file is accepted. |  |
| `strix/telemetry/logging.py` | +7/-32 | yes | upstream as generic fix | Generic dependency logging/warning suppression (litellm, asyncio, urllib3 finalizer noise). | Generic logging/telemetry cleanup; strip product banner and submit upstream. | deferred |
| `strix/telemetry/posthog.py` | +28/-19 | yes | accept upstream v1.5.2 | Revert to the upstream v1.5.2 version of this file. | No product behavior to preserve; target is byte-identical v1.5.2, so the upstream file is accepted. |  |
| `strix/telemetry/scarf.py` | +20/-18 | yes | accept upstream v1.5.2 | Revert to the upstream v1.5.2 version of this file. | No product behavior to preserve; target is byte-identical v1.5.2, so the upstream file is accepted. |  |
| `strix/tools/agents_graph/tools.py` | +18/-45 | yes | move to lyrashield/tools | Agent graph tool product adjustments (naming, redaction, bounds). | Product-specific agent graph behavior; strix reverts to v1.5.2. |  |
| `strix/tools/output_store.py` | +2/-2 | yes | move to lyrashield/tools | Product workspace spill-directory namespace (`.strix/tool-output`). | The spill path is product-branded; either make it a generic `Settings` field (upstream-eligible) or move the product path to `lyrashield/tools` and have the runner consume it via a seam. | needs-inspection |
| `strix/tools/proxy/caido_api.py` | +119/-8 | yes | move to lyrashield/runtime | Caido API sandbox interaction fixes and validation. | Product Caido/sandbox runtime hardening; called by product proxy tools. |  |
| `strix/tools/proxy/tools.py` | +53/-11 | yes | move to lyrashield/tools | Proxy tool redaction/safety and Caido result handling. | Product proxy tool policy; register via `register_agent_tools()` or product factory. |  |
| `strix/tools/reporting/tool.py` | +52/-230 | yes | move to lyrashield/artifacts | Report tool CVSS/control validation, redaction, artifact bounds. | Product report/artifact tool; belongs with artifact policy. |  |
| `strix/tools/respond/tool.py` | +1/-5 | yes | move to lyrashield/tools | Respond-to-user tool prompt wording and default argument shape. | Product tool prompt tuning; strix reverts to v1.5.2. |  |
| `strix/tools/todo/tools.py` | +6/-27 | yes | move to lyrashield/tools | Todo tool behavior (remove duplicate skipping and `skipped` field, priority normalization). | Product-specific todo schema; requires a tool-override seam or product agent builder because `register_agent_tools()` cannot replace a base tool. | needs-inspection |
| `strix/tools/web_search/__init__.py` | +2/-0 | yes | accept upstream v1.5.2 | Revert to the upstream v1.5.2 version of this file. | No product behavior to preserve; target is byte-identical v1.5.2, so the upstream file is accepted. |  |
| `strix/tools/web_search/tool.py` | +396/-156 | yes | move to lyrashield/tools | Parallel web search tool with redaction, reservation, timeout, spend accounting. | Product web search tool; requires a tool-override seam or product agent builder because it shares the `web_search` name with the upstream base tool. | needs-inspection |
| `strix/utils/api_spec.py` | 0/-312 | n/a | accept upstream v1.5.2 | Restore the upstream v1.5.2 version of this file. | No product behavior to preserve; target is byte-identical v1.5.2, so the upstream file is restored. |  |
| `strix/utils/redaction.py` | +254/-0 | no | move to lyrashield/artifacts | New redaction helpers (paths, secrets, text, Jinja tags). | Product redaction/privacy helpers used by tools, report, compaction, and lifecycle. |  |
| `strix/utils/secret_files.py` | 0/-31 | n/a | accept upstream v1.5.2 | Restore the upstream v1.5.2 version of this file. | No product behavior to preserve; target is byte-identical v1.5.2, so the upstream file is restored. |  |

## Disposition counts

Generated counts are advisory and will be refined as each slice lands.

- accept upstream v1.5.2: 89
- move to lyrashield/skills: 22
- move to lyrashield/interface/tui/: 20
- move to lyrashield/artifacts: 10
- move to lyrashield/lifecycle: 8
- move to lyrashield/tools: 6
- move to lyrashield/policy: 5
- move to lyrashield/runtime: 5
- upstream as generic fix: 3
- move to lyrashield_adapter: 3
- delete: 2
- retain as generic seam: 1
- move to lyrashield/interface/viewer/: 1

## Recommended first vertical slice

**Move all LyraShield-specific skill markdown overlays from `strix/skills/` to `lyrashield/skills/` and register the directory through `strix.skills.register_skill_dir()` from `lyrashield_adapter/cli.py`.**

This slice:
- Uses an existing, tested extension seam (no new generic seam required).
- Removes ~20 of the forked `strix/skills/**/*.md` paths and their attribution/renaming drift in one green change.
- Restores the three pure-formatting skill files (`strix/skills/README.md`, `strix/skills/frameworks/fastapi.md`, `strix/skills/vulnerabilities/insecure_deserialization.md`) and the two upstream-only skill files (`strix/skills/custom/api_spec_testing.md`, `strix/skills/technologies/firebase.md`) to v1.5.2.
- Is behavior-preserving because `register_skill_dir()` searches the registered directory before the built-in skills tree.
- Is independently verifiable with `scripts/verify-controlled-derivative.sh` and the worker contract gate.
- Creates the `lyrashield/skills/` package, establishing the pattern for later tool and runtime registration.

Files in the first slice: all changed `strix/skills/**/*.md` except the five v1.5.2 files listed above. `strix/skills/__init__.py` is accepted from v1.5.2 because it already exposes the `register_skill_dir()` seam.

## Files needing an explicit follow-up decision

The `Status = needs-inspection` rows require a design or product decision before extraction:

- `strix/agents/factory.py` (retain as generic seam): v1.5.2 already has the tool registration seam; the retained patch must be a small, documented, upstream-submittable generic extension (e.g., tool wrappers, model pass-through) and not product logic.
- `strix/interface/tui/live_view.py` (accept upstream v1.5.2): v1.5.2 `TuiLiveView` is the upstream live transcript/state manager; the fork's stripped-down version was an adaptation for the product app.
- `strix/interface/viewer/auth.py` (accept upstream v1.5.2): The fork inlined secret writing because it deleted `secret_files.py`; restoring the helper returns to v1.5.2. Verify the moved product viewer does not require the non-context-manager request style.
- `strix/tools/output_store.py` (move to lyrashield/tools): The spill path is product-branded; either make it a generic `Settings` field (upstream-eligible) or move the product path to `lyrashield/tools` and have the runner consume it via a seam.
- `strix/tools/todo/tools.py` (move to lyrashield/tools): Product-specific todo schema; requires a tool-override seam or product agent builder because `register_agent_tools()` cannot replace a base tool.
- `strix/tools/web_search/tool.py` (move to lyrashield/tools): Product web search tool; requires a tool-override seam or product agent builder because it shares the `web_search` name with the upstream base tool.

The `Status = deferred` rows are generic upstream-compatible fixes that can land after the product behavior is out of `strix/`.

- `strix/config/loader.py` (upstream as generic fix)
- `strix/interface/viewer/frontend/src/components/vulnerability/MdCodeBlock.tsx` (upstream as generic fix)
- `strix/telemetry/logging.py` (upstream as generic fix)
