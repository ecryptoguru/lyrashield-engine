# Claims ledger

Every public detection-quality claim must trace to a row here — corpus
version, engine revision, model route, run receipt, and the founder's
sign-off. A claim without a row is not publishable.

| Claim | Corpus | Engine rev | Model route | Run receipt | Approved by | Date |
|---|---|---|---|---|---|---|
| _(none yet)_ | | | | | | |

## Rules

- Claims cite `benchmarks/results/<ts>/results.json` + `RESULTS.md`; both are
  retained artifacts, not regenerated marketing numbers.
- "Detection rate" always names corpus + class scope — never "we detect X% of
  vulnerabilities" unqualified.
- Engine (LLM) numbers require `run_stability` across ≥3 runs; single-run
  results are not publishable claims.
- Deterministic-scanner numbers cite the scanner contract version
  (`packages/types` scanner contract) alongside the corpus revision.
- The upstream XBEN result belongs to Strix v0.4.0 — never quoted as
  LyraShield evidence (see README).

## Legacy receipts

All receipts produced before harnessVersion 2 are unvalidated historical runs,
not detection-quality evidence. They omitted clean controls and exact case/run
binding; their published recall and duplicate metrics must not be cited.
The unvalidated drafts were removed from the PR; Git history retains them for
audit. Generate fresh paired receipts with the corrected harness and require
COMPLETE scorer status before review.
