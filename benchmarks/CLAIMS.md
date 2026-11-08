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
- Engine claims also require retained raw run artifacts and independently
  verified executable identity and model/provider routing. The current runner
  invokes `lyrashield` from `PATH`, records the checkout revision separately,
  and deletes its temporary raw artifacts; a `COMPLETE` scorer status does
  not close those gaps.
- Deterministic-scanner numbers cite the scanner contract version
  (`packages/types` scanner contract) alongside the corpus revision.
- The upstream XBEN result belongs to Strix v0.4.0 — never quoted as
  LyraShield evidence (see README).

## Legacy receipts

Receipts produced before harnessVersion 3 are unvalidated historical runs,
not detection-quality evidence. Version 2 did not bind the exact findings
bytes; versions before 2 also omitted clean controls and exact case/run
binding. Historical `COMPLETE` labels and published recall and duplicate
metrics must not be cited. Keep historical files for audit; generate fresh
paired receipts with the corrected harness and require `COMPLETE` scorer
status before review. The version 3 digest detects findings-file changes
relative to its manifest; it is not a signature and does not detect coordinated
edits to both files.

Version 3 did not record how many engine repetitions were requested. A
complete-looking subset cannot prove the full run set, so re-scoring a v3
engine or combined receipt yields `INCOMPLETE`. Deterministic-only v3 receipts
remain readable under their existing checks. Version 4 records `engineRuns`
and requires every declared iteration for every case and polarity; incomplete
receipts do not produce an engine stability value. The declared count is not
authenticated and cannot prove that a coordinated change to the receipt and
findings did not occur. A manifest-only edit can also remove a zero-findings
iteration from every case and polarity and reduce `engineRuns` without changing
the findings bytes or digest. Existing historical results are not rewritten.
