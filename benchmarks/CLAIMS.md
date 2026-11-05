# Claims ledger

Every public detection-quality claim must trace to a row in
[`claims.json`](./claims.json), and the row must pass the executable gate:

```sh
uv run python benchmarks/validate_claims.py --ledger benchmarks/claims.json --repo-root .
```

The ledger starts empty. An empty ledger means no claim has been approved; it
does not imply a zero failure rate. Sign a report before ledger review:

```sh
uv run python -m benchmarks.report_signature sign \
  --payload benchmarks/results/<name>/results.json \
  --private-key /secure/path/report-signing-key.pem \
  --output benchmarks/results/<name>/results.sig.json
```

## Required claim binding

The validator recomputes evaluation v3 from the retained findings and manifest.
A claim must carry all of the following exact values:

- the product source revision and engine revision recorded by the clean run;
- corpus path, corpus checksum, and path profile;
- a `MEASURED` path profile, with the exact scanner contract recorded by the
  run for deterministic profiles;
- executable checksum for executable-based profiles;
- provider, model, and retained route-receipt checksum for engine profiles;
- retained, distinct receipt paths and SHA-256 values for
  `results.json`, `RESULTS.md`, `findings.jsonl`, and `run-manifest.json`;
- three declared engine runs for URL/API, local CLI, and product-integration
  claims, with complete case and polarity coverage;
- observed numerator, denominator, and claimed value; the claimed value must
  match `results.json`, and the metric must be `REPORTABLE`;
- an Ed25519 signature over retained `results.json`, plus the signature file's
  exact SHA-256;
- explicit limitations and development-or-held-out evaluation scope;
- founder approval with a timezone-bearing date;
- verified held-out label checksum when the scope is `held_out`.

An unreachable finding or scenario, an unmeasured path, ambiguity, an
unclassified finding, or incomplete evidence keeps the metric
`NOT_REPORTABLE`, even when the harness itself is `COMPLETE`.

The scorer returns `NOT_REPORTABLE` without independently adjudicated labels,
while any vulnerable-fixture finding remains unclassified, or while ambiguity
or incomplete evidence remains. A harness `COMPLETE` status is a consistency
gate for the selected runs, not proof of broader coverage or a publishable
claim.

## Rules

- Claims cite retained `benchmarks/results/<name>/results.json`,
  `RESULTS.md`, `findings.jsonl`, and `run-manifest.json`; never regenerate a
  marketing number from a selected subset.
- "Detection rate" always names corpus, class scope, path profile, and
  limitations — never an unqualified product-wide percentage.
- Engine numbers require at least three runs and the exact executable, model,
  provider, corpus, and route-receipt identities.
- Deterministic numbers cite the scanner contract version or frozen advisory
  snapshot checksum alongside the corpus revision.
- The upstream XBEN result belongs to Strix v0.4.0 and is never quoted as
  LyraShield evidence (see [README](./README.md)).
- Historical results and labels remain unchanged. Receipts before harness
  version 3 remain `LEGACY_UNVALIDATED`; v3 results without a declared engine
  run count cannot qualify engine claims.
