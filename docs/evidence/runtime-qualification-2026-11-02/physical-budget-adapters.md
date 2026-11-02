# Finite-budget provider adapter boundaries

This source qualification covers the frozen OpenAI Agents 0.19.4, OpenAI 2.48.0,
LiteLLM 1.101.3 and HTTPX 0.28.1 adapters. Deterministic offline fixtures exercise
actual SDK requests through their resolved HTTP clients. They are not provider
invoice, live model, deployment or target acceptance evidence.

A finite generation admission requires one physical POST with the configured
positive output-token limit present on the actual wire body and no larger than
its quoted limit. A per-request proxy uses the existing resolved client's
endpoint, credentials, transport, TLS, headers and cookies. It disables generation
redirects and refuses a hidden second POST. It does not change a shared client,
LiteLLM globals or a provider factory, and does not infer credentials.

| Actual resolved adapter / route class | Finite disposition | Compatibility and fallback impact |
| --- | --- | --- |
| Native OpenAI Responses or Chat Completions, including admitted bare/OpenAI GPT-6 Sol/Luna routes | Qualified; existing client and configured hard output cap retained | Streaming, nonstreaming bridge and diagnostics remain supported. HTTP 307/308 generation redirects fail after one POST. |
| Admitted Azure / Azure AI GPT-6 routes resolved by the owned provider to native SDK models, including region paths and documented wrapper aliases | Qualified through the existing resolved native client | The resolved endpoint and credentials remain authoritative. No replacement OpenAI endpoint or ambient credentials are introduced. |
| LiteLLM SDK model on an explicit `openai/` route with an explicitly resolved `AsyncOpenAI` client supplied at the owned model-call seam | Qualified only through that native-client seam, without provider/router/fallback overrides | LiteLLM's hidden 422 parameter compatibility replay is blocked before a second POST; removing the hard output cap is never an allowed finite fallback. |
| Generic LiteLLM models without that qualified route/client combination, including OpenRouter, Anthropic, non-GPT-6 Azure and custom provider adapters | Fail before any generation dispatch, with an actionable supported-native-route error | Their transport/replay/token bounds cannot be established at this seam. A finite fallback into one of these adapters also fails before dispatch. This is not a claim that every LiteLLM provider is qualified. |
| Authenticated `chatgpt/` subscription backend | Existing known zero-priced route retained | It does not consume the paid-generation allowance; its existing subscription authentication and backend behavior remain unchanged. |
| Owned root, delegate and explicit lifecycle fallback using qualified native models | Each new call requires a fresh shared-budget admission | An unknown prior attempt keeps its quote; fallback cannot reuse that allowance. |
| Direct dedupe, triage and compaction using qualified models | Same finite transport guard after their own existing quote admission | Their configured hard output cap must fit the quote. Unqualified adapters fail before dispatch. |
| Interactive main and dedicated dedupe preflight | One local finite owner shared by both probes, bound to the selected resumed run's known persisted spend | Missing usage or cancellation terminates preflight; no onward scan is admitted. Prior successful probe usage follows the existing exactly-once persistence path. |
| Optional paid Parallel Search (default off) | Existing shared and dedicated admission retained | An accepted request with lost acknowledgement retains both allowances; no verified zero-cost receipt is fabricated. |

The owned unsupported-image recovery remains precise: only its classified
capability rejection may replace image tool output with the existing placeholder.
In this checkout it starts a fresh SDK run and therefore a fresh reservation.
No rejection string proves a billing refund. The first quote stays held; salvage
continues only when another full quote fits. An unrelated 400 does not strip
images or authorize a replay. Likewise, known-safe explicit lifecycle retry and
fallback remain available only through fresh admission. Unbounded compatibility
behavior is preserved, including LiteLLM's existing 422 fallback and native
redirect handling.

Returned output without complete provider usage is preserved, but cannot release
the quote as zero spend. A bounded raw usage observer prevents the SDK's synthetic
zero placeholders and partial Chat streaming counters normalized to zero from
being mistaken for complete usage. Complete reported zero counters can reconcile
a quote; a known zero-priced route can still proceed. The observer caps a usage
frame/body at 1 MiB; oversized or unrecognized usage remains conservatively
unknown. It never changes response bytes or target evidence.

These checks enforce pre-send coverage within the admitted price/token quote.
They do not derive provider invoices from customer billing clamps. Unknown floors
are currently process-local: they are not reconstructed from a prior process's
lost acknowledgement. Durable admission/uncertainty preservation across crashes
and resume remains a separate mandatory promotion gate. Historical known-usage
records are retained; no claim is made that unknown historical charges have been
reconstructed. Paid acceptance must wait for that gate and the parent integration
and scoped review gates.
