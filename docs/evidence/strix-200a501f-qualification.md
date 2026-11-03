# Exact Strix substrate qualification: 200a501f

Evidence snapshot: 2026-11-02. Upstream commit: `200a501f15a24a4152f92897a6b72af238ee69ef`.

## Scope and status

The imported `strix/**` tree is pinned to the exact upstream commit above. Product policy and compatibility remain in `lyrashield/**` and `lyrashield_adapter/**`. This snapshot qualifies the isolated substrate and compatibility changes; complete qualification of the combined runtime and SDK upgrade remains a separate gate. No release, deployment, or live-provider acceptance is implied.

## Reviewed patch

The approved patch remains exactly four paths, +22/-201 lines, with complete patch-object digest `51682200fe3b9ec8fa2e0f998c80c095e7add114`:

| Path | Disposition |
| --- | --- |
| `strix/config/loader.py` | Product settings-loader registration seam, +20/-0. |
| `strix/skills/vulnerabilities/semantic_confusion.md` | Replace unshipped Hurl/Hypothesis references with scripting and property-harness guidance, +2/-2. |
| `strix/skills/tooling/hurl.md` | Reviewed deletion, -99. |
| `strix/skills/tooling/hypothesis.md` | Reviewed deletion, -100. |

The digest is computed with `git -c core.abbrev=7 diff --no-ext-diff --binary 200a501f -- strix/ | git hash-object --stdin`. The gate retains its strict path allowlist, footprint ceilings, and exact digest. It also rejects untracked substrate files even when ignore rules hide them, including restored deleted skills and importable modules. Only bytecode in `__pycache__` and the viewer frontend's exact `node_modules`, `dist`, and `.vite` directories are permitted generated locations. Generic build-directory names elsewhere do not create an exception.

`tests/fixtures/controlled-derivative.patch.json` preserves the exact reviewed patch as a JSON string for offline gate regression setup. The fixture is hash-checked against the digest above, reversed onto the checked-in substrate, and committed into a temporary local repository. These synthetic fixture commits preserve the original blob IDs and exact patch bytes while avoiding any dependency on upstream commit objects or network access. The real gate still fetches its actual pinned upstream commit when needed.

## Owned compatibility

- The owned request guard passes `stream_idle_timeout=None` to disable the imported guard's timer. Upstream treats zero as an immediate deadline. The owned outer timer preserves `BoundedStreamTimeoutError` provenance, distinguishes unrelated provider timeouts, and retains partial-result salvage boundaries. Both zero and None disabled settings permit a delayed first event.
- The product prompt renders upstream skill metadata as qualified names and descriptions. The owned `respond_to_user(message=...)` lifecycle, coordinator, child context policy, and tool schemas remain in place; the owned factory does not expose upstream `wait_for_user`.
- Generic upstream fixtures were refreshed for archive-based extra-file staging, request-log wrapping, MCP catalog/search/schema behavior, and report formatting. Separate product staging, reporting, billing, lifecycle, and routing tests remain in place.

## Upstream failure dispositions

The independent baseline recorded 2102 passed, 26 failed, and two warnings in 78.14 seconds on Python 3.13.14. An external pytest-timeout 15/thread bound was used only for that qualification run. Its log SHA-256 is preserved in the [fixture disposition ledger](strix-200a501f-upstream-dispositions.json).

The ledger lists all 26 original node IDs, their current local node IDs, and repairs. None is skipped or marked xfail:

- Seven budget/child-runner fixtures now supply the required `skills=[]` argument to `_start_child_runner`; the production signature is unchanged.
- Eighteen runner fixtures now supply `telemetry.run_record_timings=False`; no production telemetry fallback is added.
- One pricing fixture supplies deterministic provider-qualified sample catalog entries; resolver coverage no longer depends on future entries in the frozen LiteLLM catalog. Product pricing and receipt contracts remain separate.

The corrected family passed 55 tests, including every originally failing node ID. Additional upstream MCP, reporting, and session helper tests passed in the full suite.

## Authentication exclusion

The independent upstream baseline excluded its full `tests/test_models.py` after an unsupported OpenRouter Claude route entered GitHub Copilot device authorization. No interactive login or provider request was performed for this import. The product's supported OpenAI/Azure/ChatGPT GPT-6 routes and rejection of unsupported providers, non-GPT-6 subscription models, and forbidden configuration routes are checked with deterministic adapter tests. Generic routing helpers are exercised with isolated upstream settings and request-log wrapper unwrapping.

This exclusion covers unsupported authentication. Live-provider acceptance remains unverified. The imported timeout helper retains tests for stalled and live streams, first-event and total deadlines, configured values, and disabled nonstreaming timers. Owned streaming, nonstreaming, subscription adapters, delayed first events, provider errors, cancellation, fallback, abandoned-spend accounting, and partial-finding salvage are covered separately.

## Validation snapshot

| Check | Recorded result |
| --- | --- |
| Full suite with Pydantic deprecations treated as errors | 3109 passed, 7 skipped in 170.94s on Python 3.14.6. Two subsequently added disabled-timer cases passed in the frozen regression run. |
| Frozen Python 3.13.14 regression run covering all 26 repaired fixtures, owned routes, timeout helpers, lifecycle, prompt metadata, derivative gate, stream closing, and engine-side worker contracts | 335 passed in 23.74s. |
| Frozen controlled-derivative gate | Exact patch/path/footprint checks and frozen dependency sync with the viewer extra passed. Lint stopped at three intentional upstream lazy imports in `strix/llm/request_log.py` at 853, 900, and 913; integration needs a narrow path exception. |
| Offline gate regression after review | Seven cases passed from a fresh single-branch clone without the pinned upstream commit object, with only local Git transport allowed. Untracked source and an unstaged restored skill were rejected; ignored caches and dependencies remained permitted. |
| Ruff format | 450 files already formatted. |
| Strict mypy | 251 source files passed on Python 3.13 and 3.14. |
| Bandit LOW severity | Passed; existing nosec parser warnings only. |
| Whitespace | Owned changes passed. The exact upstream generated bundle `strix/interface/viewer/static/assets/index-B1JzV4Vu.js:455` contains trailing whitespace and is preserved unchanged. |
| Worker-consumer integration, native builds, production sandbox acceptance, live providers, and CI | Separate acceptance gates; not proven by this snapshot. Engine-side worker-contract regressions passed. |

The environments resolved openai-agents 0.19.4, openai 2.48.0, LiteLLM 1.90.7, Pydantic 2.13.4, and pytest 9.1.1. The seven full-suite skips cover three Linux supplementary-group subprocess tests, two native Win32 attachment tests, one live Linux Docker bridge-routing test, and the base-install-without-viewer check when the viewer extra is present. No skip was introduced by the import.
