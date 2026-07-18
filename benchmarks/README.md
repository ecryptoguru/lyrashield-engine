# Result-quality evaluation

LyraShield Engine currently makes no benchmark, accuracy, recall, exploit-success, or comparative result claim.

The repository's deterministic gate—329 tests plus lint, formatting, typing, Bandit, packaging, binary, sandbox, and worker-contract checks—proves implementation and compatibility properties. It does not prove that scans find every issue, avoid every false positive, or outperform another system.

## Inherited upstream reference

Strix reported a 96% result (100/104 challenges) on XBEN for Strix v0.4.0. That result belongs to the upstream project, an older release, its model/runtime configuration, and its benchmark methodology. It has not been reproduced for the current LyraShield derivative and must not be quoted as LyraShield product evidence.

Upstream details remain available in the [usestrix/benchmarks repository](https://github.com/usestrix/benchmarks/tree/main/XBEN). This link is attribution and research context, not validation of the current engine.

## Required LyraShield evaluation corpus

Before changing orchestration for claimed quality gains—or publishing any result claim—build a private, versioned corpus that records:

- approved repository snapshots and scan modes;
- expected findings and expected non-findings;
- code-location, package/CVE, evidence, and control-ID correctness;
- duplicate stability across detectors and repeated runs;
- validated, independently verified, and inconclusive outcome semantics;
- runtime, request/token buckets, cancellation, and limit behavior for Luna and Terra;
- regression thresholds and a documented adjudication process.

Keep model-based discovery separate from deterministic verification. Never promote confidence, a generated proof-of-concept, or absence in one run into independent verification. Store only privacy-bounded evaluation artifacts and never commit credentials, target secrets, raw provider payloads, or unapproved proprietary repositories.
