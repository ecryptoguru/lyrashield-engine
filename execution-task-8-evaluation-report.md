# Task 8 — evaluation v3 and critical mutation gates

## Status

Implementation is complete for the authorized repository scope.

- Base: `origin/main` at `60f7e1aa`
- Validated implementation head: `3d2b1e0a99b287c85b94a6528290bb46b2c6c456`
- Branch: `codex/evaluation-v3`
- Worktree: `/Users/defiankit/.codex/worktrees/evaluation-v3/lyrashield-engine`
- Publishable quality claims: **0**. The ledger is intentionally empty and every path profile remains `NOT_MEASURED`.
- Historical result files, provider calls, paid benchmarks, production access, push, deploy and publication: not performed.

The harness and claim contracts are finished. The absence of a quality result is an evidence boundary, not a harness failure.

## Required outcomes

| Outcome | Implementation |
|---|---|
| Versioned corpus and validator | Added `benchmarks/corpus/v3`, retained v1/v2, checksum-bound adjudication, held-out, advisory and path-profile contracts. |
| One-to-one categories | The scorer preserves true positives, false positives, false negatives, ambiguous, unreachable, unclassified extras, duplicates and incomplete records with one outcome per execution. |
| Statistical gates | Raw numerators/denominators are retained; Wilson 95% intervals and values are emitted only for reportable metrics. Unclassified, ambiguous, unreachable, incomplete and unmeasured evidence keeps metrics `NOT_REPORTABLE`. |
| Separate paths | `deterministic_core`, `offline_sca`, `url_api`, `local_engine_cli` and `product_integration` have separate profiles. Only deterministic-core and local-engine-CLI have current runners; the others fail closed until dedicated harnesses exist. |
| Independent review and held-out labels | Reviewed records require two distinct non-author reviewers, unique per-finding decisions, rationale and a timezone-bearing review date. A verified held-out contract requires checksums plus an independent reviewer and verification time. |
| Executable claims | Claims bind clean source and engine revisions, corpus and contracts, path profile, model route, executable and scanner contract, three engine runs where applicable, all retained result artifacts, recomputed metric/value, limitations, Ed25519 signature, held-out scope and founder signoff. |
| Mutation gates | Added nine isolated probes with exact one-match replacements, baseline success, killed-test identity, restored test success, SHA-256 restoration and cleanup evidence. |

## Mutation evidence

Command:

```sh
uv run python -m benchmarks.mutation_probe --timeout 180 \
  --output /tmp/lyrashield-evaluation-v3-mutations-final.json
```

Result: **PASS**, 9 of 9 probes, on implementation head `3d2b1e0a99b287c85b94a6528290bb46b2c6c456`. Evidence SHA-256: `abcd670589504751c5949491731e8eb1ea8c43b1b152e5961807071af2729733`.

| Gate | Baseline code | Killed code | Restored code | Returncodes baseline/killed/restored | Cleanup |
|---|---|---|---|---|---|
| `authorization` | `e3e9d773bf2e941e1a9672e417b8a0e8779ef210d31716c571b6a9228eec1980` | `d725ac9b6f84cf329365028f6c422589bf0c77bcfde3af84abfece8fddecf635` | `e3e9d773bf2e941e1a9672e417b8a0e8779ef210d31716c571b6a9228eec1980` | 0/1/0 | OK |
| `workspace_scope` | `732ea2831b0f7be66bb5c22f281717d1b6c51e0e500aee1815d6d95f7613f168` | `f778b817b845eadecceb3d1b88fb43b8ceae0c8b154129165b5a1d738ef25017` | `732ea2831b0f7be66bb5c22f281717d1b6c51e0e500aee1815d6d95f7613f168` | 0/1/0 | OK |
| `gate_identity` | `cdbd5f5df0e18b0df48bca62dbfebc953cd10c8368652d6a1915152dff04c25f` | `cd9b70d5d2d27e4aa7eb25b4223ad2d32be553ecf984e9be91795a360eeef957` | `cdbd5f5df0e18b0df48bca62dbfebc953cd10c8368652d6a1915152dff04c25f` | 0/1/0 | OK |
| `evidence_scope` | `85d140d53ec7c9fbe28c0b925366e0b4eaa57ec45385f799addb69125dadfc15` | `39dce9a7f600aa222c04a5892cdd4ddffa572313653bc8b0f2156dcb7708323f` | `85d140d53ec7c9fbe28c0b925366e0b4eaa57ec45385f799addb69125dadfc15` | 0/1/0 | OK |
| `cleanup_unknown` | `f8af46f8a61930254cc1332ef8005dcc1ebd6e76781c8d65e39f28e796bbc4bf` | `e5e3d993c789e3b326d417952c75f21e6aa8a86b104570ec4c4270f3bf72fe68` | `f8af46f8a61930254cc1332ef8005dcc1ebd6e76781c8d65e39f28e796bbc4bf` | 0/1/0 | OK |
| `billing_cap_replay` | `1a48c8b80c3987ec9b61d5b6e31941c78f04579cb7dc91c08012cae8b6427d5f` | `971eb0421baed5f21d3216d5ccf4c2ba62f5e1fe4a75ffac4d7c0936bc09e126` | `1a48c8b80c3987ec9b61d5b6e31941c78f04579cb7dc91c08012cae8b6427d5f` | 0/1/0 | OK |
| `cache_identity` | `d36121c24cbc85f512f2b3ca7c7f8645e407fbaa896611231d91bef2855cf692` | `8198ae1b2a1984c51753cbca43ce6e0c860e6fba91425083dbecf1b7f0d45aaa` | `d36121c24cbc85f512f2b3ca7c7f8645e407fbaa896611231d91bef2855cf692` | 0/1/0 | OK |
| `report_signature` | `d14bc5ed3d633c4b288d68a897cb17c4117a0e73f526d21bf526c04cc31bb172` | `d86539bf1f28e123847f5ddf24b16f0ee72d9789910eb6e214bab4ec3aabd5ea` | `d14bc5ed3d633c4b288d68a897cb17c4117a0e73f526d21bf526c04cc31bb172` | 0/1/0 | OK |
| `analytics_privacy` | `57fa57f14548520e879d14cabe6325ac8ba0e63dbb8556c40ad9705853aca63b` | `b10254c7b4223263029eed88d2c5d684a6e6fb8d7c14fe9ce710879fe4e66ebd` | `57fa57f14548520e879d14cabe6325ac8ba0e63dbb8556c40ad9705853aca63b` | 0/1/0 | OK |

## Verification

- `uv run pytest tests/test_evaluation_v3.py tests/test_claims_validation.py tests/test_mutation_probe.py tests/test_evaluation_corpus.py tests/test_report_signature.py tests/test_benchmark_scoring.py -q` — **92 passed**.
- `uv run pytest -q` — **4035 passed, 18 skipped**; one unrelated Docker startup-timing assertion missed its setup event in the full concurrent run.
- `uv run pytest 'tests/test_image_pull_deadline.py::test_docker_connection_inspect_and_pull_are_deadline_bound[connection]' -q` — **1 passed** on exact isolated rerun.
- `uv run python -m benchmarks.corpus.v3.validate` — passed.
- `uv run python benchmarks/validate_claims.py --ledger benchmarks/claims.json --repo-root .` — `valid: true`, `claimCount: 0`, `publishableClaims: 0`.
- `uv run ruff check .` — passed.
- `uv run ruff format --check .` — **538 files already formatted**.
- `git diff --check` — passed.

## Commits

`07f800c2`, `7dbc3e16`, `07ee26ad`, `225ffa77`, `cb51eb37`, `bdeaa273`, `c222223d`, `4186ffbe`, `77609027`, `d58c2b03`, `987f51c0`, `9a6fbedf`, `5d8aac34`, `ee965f9b`, `bd364fdd`, `68fae7ca`, `b6f4c824`, `bcd65f76`, `4e91df59`, `a50addb2`, `ffa03e61`, `6bce9fd6`, `116cac5d`, `3d2b1e0a`.

## Remaining evidence gates

- No profile is marked `MEASURED`; deterministic and engine quality numbers remain unavailable.
- Independent human adjudication is still `NOT_INDEPENDENTLY_REVIEWED`.
- The held-out contract remains `NOT_PROVIDED`; no held-out quality is implied.
- No clean paired model benchmark was run. Engine execution requires explicit spend authorization, an exact model route receipt and a clean product checkout; those were outside this task and were not invoked.
- The isolated worktree has no sibling product checkout, so a real deterministic run must receive a clean `LYRASHIELD_AI_DIR` before it can produce complete source identity.
- Mutation evidence proves the selected regression tests are sensitive to those exact mutations. It does not prove live deployment behavior, production tenant isolation or all equivalent bypasses.
