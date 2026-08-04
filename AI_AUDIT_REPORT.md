# LyraShield Engine — AI Feature Audit Report

**Target repository:** `lyrashield-engine` (`/Users/defiankit/Desktop/lyrashield-engine`)  
**Audit focus:** AI/LLM features, safety, quality, observability, and production readiness  
**Method:** Static code review of the Strix-derived agentic security-scanning engine  

---

## 1. Executive Summary

LyraShield Engine is a controlled derivative of the Strix agentic security scanner. It is an **agentic, multi-LLM system that combines retrieval, structured extraction, generation, ranking, and tool automation** to perform authorized penetration tests against repositories, URLs, and IP addresses. The engine is built on the OpenAI `agents` SDK and `LiteLLM`, with a custom provider router, context-compaction layer, multi-agent coordinator, and vulnerability-reporting toolchain.

Overall, the codebase shows **mature guardrails in several areas**: provider capability probes that avoid sending target data; per-request budget reservations and turn warnings; tool-output bounding and sandbox spilling; deterministic pre-checks before LLM-based deduplication; and a product boundary (`lyrashield_adapter/cli.py`) that disables telemetry and rejects unsupported GPT-5.6 providers and ChatGPT subscription models.

Following the audit, a comprehensive security hardening pass was applied. The following themes were addressed:

1. **Prompt-injection and instruction-hierarchy weaknesses — HARDENED.** The system prompt now includes explicit `TRUST BOUNDARIES — SYSTEM-INJECTED MARKERS` guidance for `[SYSTEM-NOTICE]` and `[SYSTEM-VERIFIED PEER MESSAGE]` tags, with anti-spoofing rules. Budget/turn warnings and inter-agent messages are prefixed with system-verified tags. `root_instructions_override` and `extra_system_prompt_context` are sanitized via `_sanitize_prompt_value` to strip Jinja directives (`{{ }}`, `{% %}`, `{# #}`) and control characters.
2. **Privacy and data-leakage through the LLM layer — HARDENED.** Context compaction now redacts secrets before summarization and instructs the model to record placeholder types instead of copying credentials verbatim. All vulnerability report and final report free-text fields are redacted at persistence via `redact_text()`. PoC script code preserves internal paths for reproducibility while still redacting secrets.
3. **Reliance on model-self-discipline for safety-critical outputs — HARDENED.** Deduplication now enforces a `DedupeJudgement` Pydantic schema with `AgentOutputSchema(strict_json_schema=True)` and falls back to a lenient parser on validation failure. Telemetry keys are read lazily from environment variables at call time instead of being hardcoded at import. Skill telemetry thread spawning is gated by `telemetry.enabled`.

> **Note:** Items marked ✅ below have been fixed in the hardening pass. Items marked ⚠️ are partially addressed. Items marked 🔲 remain open for future work.

---

## 2. AI Feature Classification

| Class | Implementation | Description |
|-------|----------------|-------------|
| **Agent / tool automation** | `strix/agents/factory.py`, `strix/core/runner.py`, `strix/core/execution.py`, `strix/tools/agents_graph/tools.py`, `strix/core/agents.py` | Multi-agent system with root/child agents, `create_agent`, `send_message_to_agent`, `wait_for_agents`, `finish_scan` / `agent_finish` lifecycle tools, filesystem/shell/custom tool sets. |
| **Retrieval** | `strix/tools/web_search/tool.py`, `strix/skills/__init__.py`, `strix/tools/load_skill/tool.py` | Optional Parallel Search web retrieval with query redaction; skill markdown loaded at agent build time or in-conversation via `load_skill`. |
| **Extraction** | `strix/tools/reporting/tool.py`, `strix/provider_contract.py` | Extraction of CVSS, CWE, CVE, endpoint/method, and code locations; provider capability probes. |
| **Ranking** | `strix/report/dedupe.py` | Deterministic identity checks plus an LLM judge to avoid duplicate vulnerability reports. |
| **Generation** | `strix/llm/compaction.py`, `strix/tools/finish/tool.py`, `strix/agents/prompts/system_prompt.jinja` | Conversation summarization, executive report generation, Jinja-rendered dynamic system prompts. |

---

## 3. System Boundary Map

| Boundary Layer | Components | Notes |
|----------------|------------|-------|
| **Inputs** | `scan_config` (`targets`, `scan_mode`, `user_instructions`, `diff_scope`), `root_instructions_override`, `extra_system_prompt_context`, interactive user messages, inter-agent messages, tool outputs. | `strix/core/runner.py:163-178`, `strix/core/inputs.py:200-227` build the root task and scope context. |
| **Retrieval sources** | Built-in skill markdown (`strix/skills/`), optionally user-registered skill dirs, Parallel Search (`strix/tools/web_search/tool.py`). | Skills are loaded by `strix/skills/__init__.py:202-238`; web search is disabled by default. |
| **Model calls** | `StrixProvider` (`strix/config/models.py:360-436`) routes through OpenAI SDK or LiteLLM. `provider_contract.py` probes capabilities. `compaction.py` calls the model to summarize history. `dedupe.py` calls a dedupe model. | Two models may be configured (`model` and `delegate_model`). `make_model_settings` in `strix/core/inputs.py:230-250`. |
| **Validation steps** | `is_gpt56_model` / `is_gpt56_supported_provider` (`strix/config/models.py`), `validate_requested_skills` (`strix/skills/__init__.py:156-180`), CVSS/CWE/CVE validation in `strix/tools/reporting/tool.py:88-127`, code-location path validation (`_validate_file_path`), budget/turn checks in `strix/core/hooks.py:472-792`. | Strong format validation for reports; weaker content validation. |
| **Outputs** | `vulnerabilities.json`, `run.json`, SARIF, executive report markdown, per-run usage/cost ledger, tool-output spill files. | `strix/report/state.py:490-515` persists artifacts. |
| **Logging / monitoring** | Structured logging per run, `LLMUsageLedger` (`strix/report/usage.py`), optional PostHog/Scarf telemetry (disabled for LyraShield). | Telemetry disabled by `strix/telemetry/__init__.py:9`. |

---

## 4. Core Concern Audit Findings

### 4.1 Factual Grounding

| ID | Finding | Severity | Location | Guardrail present | Gap | Recommended fix |
|----|---------|----------|----------|-------------------|-----|-----------------|
| F1 ✅ | **Context compaction prompt no longer instructs verbatim credential preservation.** The summary prompt now instructs the model to record placeholder types (e.g. `[SECRET]`) instead of copying secrets. Conversation head and summary are redacted via `redact_text()` before summarization and storage. No post-hoc fidelity check is implemented yet. | **Medium → Low** | `strix/llm/compaction.py:86-135` (summary prompt), `strix/llm/compaction.py:388-422` (redaction) | `maybe_compact` falls back to no-op if the summary is empty; `_fit_to_tokens` truncates based on token budget. | No fidelity check, no source-attribution in summary. | Add a deterministic fact-check: require the summary to include source item references; sample-verify summaries against source on a validation model; or use a structured summary schema. |
| F2 | **Deduplication LLM judge is given truncated/partial history and can make wrong decisions.** Existing reports are truncated to `200k` chars (`_MAX_EXISTING_REPORTS_CHARS`) and individual fields to `8k` chars. The model may miss nuance. | **Medium** | `strix/report/dedupe.py:175-180`, `strix/report/dedupe.py:298-330` | Deterministic identity checks run first; bounded payload protects cost. | Truncation can remove the distinguishing evidence needed for a correct duplicate decision. | Use a two-stage dedupe: exact identity → embedding/semantic hash → LLM only for borderline cases; preserve full identity fields without truncation. |
| F3 | **Web search results are not cited/grounded before being used for exploit/CVE claims.** `web_search/tool.py` redacts queries but does not attach source URLs or confidence to results. | **Low** | `strix/tools/web_search/tool.py:1-200` | Query redaction and topic allowlist. | No source-citation requirement; model may conflate OSINT with target evidence. | Require citations in search results; expose source URLs and dates in the tool result; validate CVE/package matches against installed versions before reporting. |

### 4.2 Structured Output Reliability

| ID | Finding | Severity | Location | Guardrail present | Gap | Recommended fix |
|----|---------|----------|----------|-------------------|-----|-----------------|
| S1 ✅ | **Dedupe response now uses a Pydantic schema with strict JSON enforcement.** `DedupeJudgement` Pydantic model with `AgentOutputSchema(strict_json_schema=True)` is applied. Fallback to lenient `_parse_dedupe_response` on validation failure. | **High → Resolved** | `strix/report/dedupe.py:10-35` (schema), `strix/report/dedupe.py:185-269` (request), `strix/report/dedupe.py:530-569` (parser) | Fallback deterministic identity; parser handles markdown fences and balanced braces. | — | — |
| S2 ✅ | **Vulnerability report fields are now redacted at persistence.** `redact_text()` is applied to all free-text fields (`description`, `impact`, `technical_analysis`, `poc_description`, `evidence`, `assumptions`, `remediation_steps`, `fix_pr_body`) in `ReportState.add_vulnerability_report`. Internal path redaction is mode-aware: whitebox scans preserve `/workspace/<subdir>` target paths; blackbox scans redact them. PoC script code always preserves internal paths for reproducibility. Spill paths (`/workspace/.strix/tool-output/`) and tmp state (`/tmp/.strix`) are always redacted. | **High → Resolved** | `strix/report/state.py:269-312` (report fields), `strix/utils/redaction.py:104-176` (redaction patterns) | System prompt instructs not to leak internal details. | — | — |
| S3 | **`create_vulnerability_report` is defined with `strict_mode=False`.** While server-side validation is robust, the SDK hint to enforce the schema is off, increasing the chance the model will invent unsupported parameters. | **Low** | `strix/tools/reporting/tool.py:361` | Tool body validates every parameter. | Subtle SDK behavior changes could weaken validation. | Evaluate `strict_mode=True` after confirming all parameter types are compatible; otherwise wrap the tool with a schema validator. |
| S4 ✅ | **Final executive report fields are now redacted at persistence.** `redact_text()` is applied to `executive_summary`, `methodology`, `technical_analysis`, and `recommendations` in `ReportState.update_scan_final_fields` with mode-aware internal path redaction. | **Medium → Low** | `strix/tools/finish/tool.py:82-291`, `strix/report/state.py:395-410` | Pre-flight checklist in the prompt and active-agent check in code. | No length/structure validator or banned-phrase list yet. | Add a validator: minimum/maximum length, required headings, banned phrase list, and a check that at least one `list_reports` call preceded `finish_scan` if vulnerabilities were found. |

### 4.3 Fallback Behavior

| ID | Finding | Severity | Location | Guardrail present | Gap | Recommended fix |
|----|---------|----------|----------|-------------------|-----|-----------------|
| B1 | **Generic `APIError` is treated as transient and retried, which can loop on provider guardrails or content-policy errors.** `_is_transient_model_error` returns `True` for any `APIError` whose status code or nature is not specifically excluded. | **Medium** | `strix/core/execution.py:126-136` | `codex.is_content_guardrail_error` is excluded; connection/timeout errors are retried. | `APIError` includes 4xx provider errors (e.g., content policy, auth, bad request) that should not be retried or should be retried only selectively. | Classify provider errors explicitly: do not retry 400/401/403/422 content or auth errors; log refusal reason; distinguish transient 5xx. |
| B2 | **Context-overflow detection is message-string-based and may misclassify other `BadRequestError`s.** `is_context_overflow` falls back to matching substrings in the error message, with only a short exclusion list for rate-limit terms. | **Low** | `strix/llm/compaction.py:69-83` | Checks LiteLLM `ContextWindowExceededError` first. | OpenRouter/plain `BadRequestError` messages are heuristically matched; a non-overflow 400 could trigger compaction, and a throttled 429 with an overflow-like phrase could be misclassified. | Maintain a provider-specific error-code map; prefer provider `code`/`type` fields over substring matching; add test cases. |
| B3 | **Compaction failure is silent and leaves the session unchanged, which may lead to a context-window crash on the next request.** If `_summarize` returns `None`, `maybe_compact` returns `False` and logs a warning. No escalation. | **Medium** | `strix/llm/compaction.py:391-413` | `force=False` prevents repeated compaction attempts unless the token budget is exceeded. | A failed summary means the full context is still sent; the next model call may exceed the window and fail. | Escalate on compaction failure: truncate oldest non-essential tool outputs, fail the agent with a clear status, or pause for operator input. |
| B4 | **`count_tokens` falls back to UTF-8 byte length, causing overestimation for non-Latin text and premature compaction.** | **Low** | `strix/llm/context_budget.py` (token-count fallback); `strix/config/settings.py:214-218` (`fallback_context_tokens=200000`) | Conservative upper bound protects against overflow. | Wasted tokens and unnecessary cost for CJK or multi-byte scripts. | Use a tokenizer fallback appropriate to the model family (`tiktoken` for OpenAI, LiteLLM `token_counter` more broadly, or cached tokenizers). |

### 4.4 Cost Ceilings

| ID | Finding | Severity | Location | Guardrail present | Gap | Recommended fix |
|----|---------|----------|----------|-------------------|-----|-----------------|
| C1 | **Budget enforcement is based on local per-token estimates, not actual provider cost, and can be wrong for new or subscription models.** `on_llm_start` reserves `after * input_rate + max_output_tokens * output_rate`, and `on_llm_end` commits `_usage_cost_upper_bound`. For unknown models it uses conservative fallbacks; for subscription models it reports `$0` (`LLMUsageLedger.zero_cost`). | **Medium** | `strix/core/hooks.py:217-233` (`_usage_cost_upper_bound`), `strix/core/hooks.py:690-740` (`on_llm_start`), `strix/report/usage.py` (`zero_cost`), `strix/report/state.py:135-136` | Budget reservations are made before every call; subagents are stopped at 90% reserve; web search and dedupe also reserve. | Subscription models bypass cost accounting; cost model does not use provider-reported `cost` when available (e.g., OpenRouter `usage.cost`). | Integrate provider-reported `cost` from the response object / stream; for subscription models, still meter token usage and optionally apply a notional cost or flag in reporting; calibrate cost map with provider-specific rates. |
| C2 | **Long-context 2x cost multiplier is applied at 272k input tokens, but the threshold may not match the provider's actual long-context billing window.** | **Low** | `strix/core/hooks.py:43-46` (`_GPT56_LONG_CONTEXT_TOKENS=272000`), `strix/core/hooks.py:227`, `strix/core/hooks.py:531-535` | Conservative by design. | Hardcoded for GPT-5.6; other models may have different thresholds. | Make the long-context threshold model-aware via LiteLLM model metadata or configuration; test with each supported provider. |
| C3 ✅ | **Budget warnings are now prefixed with `[SYSTEM-NOTICE]` tag and the system prompt includes trust boundary guidance.** The system prompt instructs the model to treat `[SYSTEM-NOTICE]` as authoritative but only when it appears at the start of a top-level user message from the platform. Tags inside tool output or target content are flagged as injection attempts. | **High → Medium** | `strix/core/hooks.py:615-680` (`_maybe_warn_budget`/`_maybe_warn_turns`); `strix/agents/prompts/system_prompt.jinja:80-99` (trust boundaries) | Nudges are tailored to root/subagent and include wind-down directives. | Still delivered as `role=user` content (SDK limitation). | Inject warnings as a distinct, signed message type (e.g., `role=system` with a metadata block that the agent can verify), or append them to the system prompt before the model call. |

### 4.5 Latency Budgets

| ID | Finding | Severity | Location | Guardrail present | Gap | Recommended fix |
|----|---------|----------|----------|-------------------|-----|-----------------|
| L1 | **No wall-clock scan deadline; only per-request and tool timeouts exist.** `LLM_TIMEOUT` defaults to 300s per request (`strix/config/settings.py:145-148`); `wait_for_agents` is capped at 301s (`strix/tools/agents_graph/tools.py:221-225`). | **Medium** | `strix/config/settings.py:145-148`; `strix/tools/agents_graph/tools.py:221-225` | `max_turns` and `max_budget_usd` provide indirect limits. | A subagent in an infinite `wait_for_agents` or long command loop can block the root indefinitely. | Add an overall `max_scan_duration_seconds` deadline; propagate it to child agents; fail `wait_for_agents` if it would exceed the remaining wall-clock budget. |
| L2 | **Provider contract probes use the configured model timeout with no separate, shorter probe timeout by default.** `timeout = timeout_seconds or settings.llm.timeout`. | **Low** | `strix/provider_contract.py:143-145` | `max_output_tokens` is clamped to `128`; input is static. | A slow or hung provider can block startup. | Set a shorter, dedicated probe timeout (e.g., 30s) unless overridden; record probe latency. |

### 4.6 Privacy Exposure

| ID | Finding | Severity | Location | Guardrail present | Gap | Recommended fix |
|----|---------|----------|----------|-------------------|-----|-----------------|
| P1 ✅ | **Compaction now redacts secrets before summarization.** The conversation head is redacted via `redact_text()` before being sent to the model. The summary prompt no longer instructs verbatim credential preservation — it instructs the model to record placeholder types. The summary is redacted again before checkpointing. | **Critical → Resolved** | `strix/llm/compaction.py:112-125` (summary prompt); `strix/llm/compaction.py:388-422` (redaction in `maybe_compact`) | `strix/tools/output_store.py` bounds tool results. | — | — |
| P2 ✅ | **Telemetry keys are now read lazily from environment variables.** PostHog API key and host are read via `_posthog_api_key()` / `_posthog_host()` at call time from `STRIX_POSTHOG_API_KEY` / `STRIX_POSTHOG_HOST`. Scarf endpoint is read via `_scarf_endpoint()` from `STRIX_SCARF_ENDPOINT`. No hardcoded keys remain in source. | **Medium → Resolved** | `strix/telemetry/posthog.py:21-26` (lazy helpers); `strix/telemetry/scarf.py:25-26` (lazy helper) | `TelemetrySettings.enabled` defaults to `False`; LyraShield adapter disables telemetry. | — | — |
| P3 ✅ | **Skill telemetry thread is now gated by `telemetry.enabled`.** `_track_skill_loaded` checks `load_settings().telemetry.enabled` before spawning the telemetry thread. | **Low → Resolved** | `strix/skills/__init__.py:180-197` (`_track_skill_loaded`) | `posthog.skill_loaded`/`scarf.skill_loaded` return early if disabled. | — | — |
| P4 | **Web search redacts common secret patterns but not all, and target hostnames can still be sent when `topic != public-endpoints`.** | **Medium** | `strix/tools/web_search/tool.py:82-139` (`_SENSITIVE_PATTERNS`), `strix/tools/web_search/tool.py:144-161` (`_redact_query`) | Redaction list includes UUID, email, IP, bearer, API key, password, long hex/random; target hosts are replaced with `[TARGET]` except in `public-endpoints`. | JWTs, AWS keys, DB connection strings, and bespoke secret formats are not covered. | Expand redaction patterns; add a generic high-entropy token detector; validate that no target-internal hostnames leak outside the `public-endpoints` topic. |
| P5 | **Spilled tool-output files are written to `/workspace/.strix/tool-output/<id>.txt` with no per-run cleanup or access restriction.** | **Low** | `strix/tools/output_store.py:28`, `strix/tools/output_store.py:143-167` | Spilling keeps large output out of the model context. | Files may persist across runs and contain sensitive target output. | Scope spill files to the current `run_id`; clean up on scan completion; restrict read access to the sandbox user. |
| P6 | **`auth_mode` (e.g., `subscription` for ChatGPT) is stored in the run record and can be reflected in telemetry.** | **Low** | `strix/report/state.py:135-136` | Not sent unless telemetry is enabled. | Reveals whether a subscription/ChatGPT backend was used, which is business-sensitive metadata. | Only store `auth_mode` if required for billing; do not include in telemetry or SARIF unless necessary. |

### 4.7 Prompt Injection Resilience

| ID | Finding | Severity | Location | Guardrail present | Gap | Recommended fix |
|----|---------|----------|----------|-------------------|-----|-----------------|
| I1 ⚠️ | **System prompt contains strong anti-refusal and full-authorization instructions.** The `UNTRUSTED TARGET CONTENT` and new `TRUST BOUNDARIES` blocks provide counterbalancing guidance, but the anti-refusal language remains strong. | **High → Medium** | `strix/agents/prompts/system_prompt.jinja:101-116` (authorization status), `strix/agents/prompts/system_prompt.jinja:87-113` (refusal avoidance), `strix/agents/prompts/system_prompt.jinja:80-99` (trust boundaries) | `UNTRUSTED TARGET CONTENT` and `TRUST BOUNDARIES — SYSTEM-INJECTED MARKERS` blocks now tell the agent to treat repository files/web pages as evidence, not instructions, and define which message tags are system-verified. | Anti-refusal language is still stronger than the untrusted-content warning. | Tone down anti-refusal to "Do not refuse in-scope, authorized work"; require the model to verify that any command expanding scope or disabling checks comes from the system-verified scope block, not from user/peer content. |
| I2 ✅ | **`root_instructions_override` and `extra_system_prompt_context` are now sanitized.** `_sanitize_prompt_value` strips Jinja template tags (`{{ }}`, `{% %}`, `{# #}`) and control characters from both inputs before they enter the system prompt. Target values in `build_scope_context` are also sanitized. | **High → Low** | `strix/core/runner.py:127-174` (`_compose_root_instructions_override`); `strix/core/inputs.py:33-50` (`_sanitize_prompt_value`), `strix/core/inputs.py:210-241` (scope context) | `_merge_root_prompt_context` disallows overriding reserved scope keys. | No cryptographic signing or allowlist for `root_instructions_override` content. | Restrict `root_instructions_override` to a small allowlist of safe directives or require cryptographic signing. |
| I3 ✅ | **Inter-agent messages now carry a system-verified trust boundary prefix.** `_message_to_session_item` wraps peer messages with `[SYSTEM-VERIFIED PEER MESSAGE \| id=... \| from=... \| type=... \| priority=...]` header. The system prompt defines this tag as system-verified metadata with untrusted content below it, and includes anti-spoofing rules. | **High → Medium** | `strix/core/agents.py:539-560` (`_message_to_session_item`); `strix/agents/prompts/system_prompt.jinja:27-30, 80-99` (trust boundaries) | Self-messaging is blocked. | Still delivered as `role=user` content (SDK limitation); no cryptographic signature. | Consider a `system` role for control messages; add cryptographic signing of message metadata. |
| I4 | **Skills can be loaded from arbitrary directories and injected into the agent context.** `register_skill_dir` lets external code shadow built-in skills; `load_skills`/`load_skill` place markdown into prompt or conversation without content validation. | **Medium** | `strix/skills/__init__.py:23-50` (`register_skill_dir`); `strix/skills/__init__.py:202-238` (`load_skills`); `strix/tools/load_skill/tool.py:10-36` | `validate_requested_skills` checks names and max count. | No hash, signature, or content allowlist; a malicious skill can override the system prompt. | Load skills only from built-in paths by default; if `register_skill_dir` is used, require a manifest and signed content hashes; disable `load_skill` for custom skill directories. |
| I5 | **Programmatic tool calling lets the model generate code that invokes tools; the generated code is not obviously sandboxed or restricted.** | **High** | `strix/agents/factory.py:230-260` (`build_strix_agent` adds `ProgrammaticToolCallingTool`); `strix/provider_contract.py:161-177` (capability probe) | Capability probe verifies the provider supports programmatic calling. | `ProgrammaticToolCallingTool` (from `agents.tool`) can execute arbitrary generated code; if the model is tricked, it may call tools outside scope. | Audit the SDK `ProgrammaticToolCallingTool` sandbox; restrict which tools are callable programmatically; require human approval for generated code in interactive mode; log all generated code. |
| I6 ✅ | **Target values are now sanitized before Jinja rendering.** `_sanitize_prompt_value` strips Jinja tags (`{{ }}`, `{% %}`, `{# #}`) and control characters from target values in `build_scope_context`. | **Low → Resolved** | `strix/core/inputs.py:33-50` (`_sanitize_prompt_value`), `strix/core/inputs.py:210-241` (scope context) | `build_scope_context` converts values to strings and sanitizes them. | — | — |

---

## 5. Strengths and Existing Guardrails

- **Provider contract probes avoid target data.** `probe_provider_contract` uses only static "READY"/"CONTINUED"/marker-tool requests (`strix/provider_contract.py:128-201`).
- **Per-request budget reservation and turn warnings.** `ReportUsageHooks` reserves before each call, warns at 70/85/95% bands, and stops subagents at 90% (`strix/core/hooks.py:472-792`).
- **Tool output bounding and spilling.** Large results are truncated and saved to the sandbox, keeping the model context small (`strix/tools/output_store.py:143-167`).
- **Model gating and product boundary.** `lyrashield_adapter/cli.py` enforces supported GPT-5.6 providers and disables ChatGPT subscriptions/telemetry for the product entry point.
- **Deterministic deduplication pre-checks.** Before calling the dedupe model, the code checks exact dependency identity (`cve`+`package`) and dynamic identity (`target`+`endpoint`+`method`+`location`+`cwe`+`title`) (`strix/report/dedupe.py:333-467`).
- **Context compaction preserves tool-call/tool-result pairing.** `_select_split` and `_history_groups` avoid orphaned outputs (`strix/llm/compaction.py:202-219`, `strix/core/hooks.py:257-280`).
- **Strong report-field validation.** `create_vulnerability_report` validates required fields, CVSS, CVE/CWE format, and code-location path constraints (`strix/tools/reporting/tool.py:88-127`, `149-160`).

---

## 6. Recommended Fixes (Prioritized)

### Immediate (P0) — Block shipping or limit blast radius

1. ✅ **Redact/compartmentalize secrets in context compaction.** Secrets are now redacted via `redact_text()` before summarization. The compaction prompt instructs the model to record placeholder types instead of copying credentials verbatim.
2. ✅ **Enforce an output schema for vulnerability deduplication.** `DedupeJudgement` Pydantic schema with `AgentOutputSchema(strict_json_schema=True)` is now used, with deterministic fallback on validation failure.
3. ✅ **Add runtime output hygiene filters to vulnerability and executive reports.** `redact_text()` is applied to all free-text fields in `add_vulnerability_report` and `update_scan_final_fields`. Internal path redaction is mode-aware (whitebox preserves target paths, blackbox redacts them). PoC script code preserves paths for reproducibility.
4. ⚠️ **Harden the system prompt against injection from user/peer messages.** `[SYSTEM-NOTICE]` and `[SYSTEM-VERIFIED PEER MESSAGE]` trust boundary tags added with anti-spoofing rules. Budget/turn warnings prefixed with `[SYSTEM-NOTICE]`. Inter-agent messages wrapped with system-verified metadata header. Anti-refusal language remains strong — toning it down is still recommended.

### Short-term (P1) — Reduce risk and improve reliability

5. ✅ **Sanitize and validate `root_instructions_override` and `extra_system_prompt_context`.** `_sanitize_prompt_value` strips Jinja tags (`{{ }}`, `{% %}`, `{# #}`) and control characters from both inputs and target values.
6. ✅ **Improve inter-agent message integrity.** Messages are tagged with `[SYSTEM-VERIFIED PEER MESSAGE]` metadata header (id, from, type, priority). The system prompt defines this tag as system-verified with anti-spoofing rules.
7. 🔲 **Classify provider errors precisely and avoid retrying content/auth failures.** Vendor a stable retry status list instead of using `litellm._should_retry` and generic `APIError`.
8. 🔲 **Add a wall-clock scan deadline and propagate it through `wait_for_agents` and tool timeouts.**
9. 🔲 **Fix cost accounting for subscription models.** Record token usage and a notional/list cost even when `zero_cost=True`; integrate provider-reported cost when available.

### Medium-term (P2) — Hardening and observability

10. 🔲 **Restrict skill loading to trusted, signed skill packs.** Remove or gate `register_skill_dir` and `load_skill` for untrusted callers.
11. 🔲 **Audit and constrain `ProgrammaticToolCallingTool`.** Restrict which tools are callable, sandbox generated code, and log it.
12. ✅ **Improve telemetry privacy.** Telemetry keys are now read lazily from environment variables (`STRIX_POSTHOG_API_KEY`, `STRIX_POSTHOG_HOST`, `STRIX_SCARF_ENDPOINT`) at call time. No hardcoded keys in source. Skill telemetry thread gated by `telemetry.enabled`.
13. 🔲 **Improve token-count fallbacks.** Use model-family-appropriate tokenizers instead of UTF-8 byte length.
14. 🔲 **Add a fidelity/grounding check for compaction summaries** and verify they are traceable to source items.

---

## 7. Conclusion

LyraShield Engine has a solid engineering foundation for an agentic AI security scanner: model gating, cost reservations, context management, and tool-output bounding are all in place. The security hardening pass addressed the most critical risks: secrets are now redacted before LLM summarization, deduplication enforces a Pydantic schema, vulnerability and final report fields are redacted at persistence, inter-agent messages carry system-verified trust boundary tags, prompt inputs are sanitized against Jinja injection, and telemetry keys are externalized to environment variables. Remaining risks are concentrated in areas that require SDK-level changes (system-role messages for budget warnings), provider error classification, wall-clock deadlines, and skill pack signing — these are tracked as open items in the prioritized fix list above.
