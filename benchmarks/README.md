# Result-quality evaluation

LyraShield Engine currently makes no benchmark, accuracy, recall, exploit-success, or comparative result claim.

The repository's deterministic gate—329 tests plus lint, formatting, typing, Bandit, packaging, binary, sandbox, and worker-contract checks—proves implementation and compatibility properties. It does not prove that scans find every issue, avoid every false positive, or outperform another system.

## Inherited upstream reference

Strix reported a 96% result (100/104 challenges) on XBEN for Strix v0.4.0. That result belongs to the upstream project, an older release, its model/runtime configuration, and its benchmark methodology. It has not been reproduced for the current LyraShield derivative and must not be quoted as LyraShield product evidence.

Upstream details remain available in the [usestrix/benchmarks repository](https://github.com/usestrix/benchmarks/tree/main/XBEN). This link is attribution and research context, not validation of the current engine.

## LyraShield evaluation corpus

The versioned starter corpora live in [`corpus/v1`](./corpus/v1/README.md) and [`corpus/v2`](./corpus/v2/corpus.json). The benchmark runner defaults to v2. See the [corpus inventory](./CORPUS-INVENTORY.md) for their contents, missing fixtures, and evaluation limits. Model-quality measurements remain separate bounded runs with retained receipts.

When scoring bound records, malformed non-null finding file, rule ID, or line fields invalidate the receipt instead of earning case-match credit. Missing locations remain unmatched; a corpus-declared absence control can still match without a line. Existing historical receipts are not rewritten.

A successful run must record an integer zero process return code. Missing or non-integer values make the result incomplete; this validation does not authenticate a manifest or detect intentional manifest-only edits.

## Evaluation requirements

Before changing orchestration for claimed quality gains—or publishing any result claim—build a private, versioned corpus that records:

- approved repository snapshots and scan modes;
- expected findings and expected non-findings;
- code-location, package/CVE, evidence, and control-ID correctness;
- duplicate stability across detectors and repeated runs;
- validated, independently verified, and inconclusive outcome semantics;
- runtime, request/token buckets, cancellation, and limit behavior for Luna and Sol;
- regression thresholds and a documented adjudication process.

Keep model-based discovery separate from deterministic verification. Never promote confidence, a generated proof-of-concept, or absence in one run into independent verification. Store only privacy-bounded evaluation artifacts and never commit credentials, target secrets, raw provider payloads, or unapproved proprietary repositories.
