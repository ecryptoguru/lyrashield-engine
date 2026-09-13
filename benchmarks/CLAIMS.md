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
