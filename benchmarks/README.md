# Result-quality evaluation

LyraShield Engine currently makes no benchmark, accuracy, recall, exploit-success, or comparative result claim.

The repository's deterministic gate—329 tests plus lint, formatting, typing, Bandit, packaging, binary, sandbox, and worker-contract checks—proves implementation and compatibility properties. It does not prove that scans find every issue, avoid every false positive, or outperform another system.

## Inherited upstream reference

Strix reported a 96% result (100/104 challenges) on XBEN for Strix v0.4.0. That result belongs to the upstream project, an older release, its model/runtime configuration, and its benchmark methodology. It has not been reproduced for the current LyraShield derivative and must not be quoted as LyraShield product evidence.

Upstream details remain available in the [usestrix/benchmarks repository](https://github.com/usestrix/benchmarks/tree/main/XBEN). This link is attribution and research context, not validation of the current engine.

## LyraShield evaluation corpus

The versioned corpora live in [`corpus/v1`](./corpus/v1/README.md), [`corpus/v2`](./corpus/v2/corpus.json), and [`corpus/v3`](./corpus/v3/README.md). V3 keeps the historical cases, adds PHP and frozen-SCA fixtures, records identity/retest and partial-result scenarios, and binds adjudication, held-out, advisory, and path-profile contracts. The runner defaults to v3 and scores one-to-one outcomes with raw denominators and Wilson intervals only when the claim gates are reportable. See the [corpus inventory](./CORPUS-INVENTORY.md) for historical contents and limits.

When scoring bound records, malformed non-null finding file, rule ID, or line fields invalidate the receipt instead of earning case-match credit. Missing locations remain unmatched; a corpus-declared absence control can still match without a line. Existing historical receipts are not rewritten.

The [original evaluation execution report](../execution-task-8-evaluation-report.md) retains evidence for implementation head `3d2b1e0a`, including its failed Docker timing assertion. Its completion statement applies to that earlier repository task, not current runtime qualification or the new integration revision. The deadline fixture repair and refreshed source require their own verification; no historical result is relabeled successful.

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


## Evaluation v3 commands

```sh
uv run python -m benchmarks.corpus.v3.validate
uv run python benchmarks/run.py --corpus v3 --detectors deterministic --path-profile deterministic_core
uv run python benchmarks/score.py --corpus v3 --results benchmarks/results/<name>
uv run python benchmarks/validate_claims.py --ledger benchmarks/claims.json --repo-root .
uv run python -m benchmarks.mutation_probe --list
```

Path profiles are separate records in
[`profiles/v1/paths.json`](./profiles/v1/paths.json). `url_api`, `offline_sca`,
`local_engine_cli`, and `product_integration` remain `NOT_MEASURED` until their
own exact runs and receipts exist. The current runner only executes
`deterministic_core` and `local_engine_cli`; it rejects the other v3 profiles
until dedicated harnesses and their required bindings exist. A
deterministic-core run cannot stand in for another path.

### Offline Composer diagnostic

The local probe below runs the product's resolved dependency inventory and SCA
scanner on a separately versioned synthetic Composer pair based on
`PHP-COMPOSER-01`, using the checksum-bound synthetic advisory snapshot. It
requires an installed product checkout and creates a new output directory:

```sh
LYRASHIELD_AI_DIR=/path/to/lyrashield-ai \
  uv run python -m benchmarks.offline_sca_probe --output /path/to/new/receipt-directory
```

This diagnostic fixture set does not alter or execute the frozen v3 case bytes.
The receipt binds the input files, source states, runner, local runtime shim,
and retained result bytes. It records no qualified image or model route. The
runner supplies a frozen advisory batch, denies fetch requests, and removes
developer service configuration from the scanner process; this is not an
operating-system network isolation proof. Its six other SCA corpus cases are
TypeScript placeholders, not lockfiles. None of the v3 SCA cases are evaluated
by this probe.
The existing full-profile runner and scoring gates remain closed. All profiles
remain `NOT_MEASURED`, independent adjudication is not complete, and held-out
data is not provided. No benchmark claim follows from this diagnostic.

### Local URL/API diagnostic

The following diagnostic runs the product URL and OpenAPI scanners through the
product's scan-scoped relay to a synthetic HTTPS target bound to loopback:

```sh
LYRASHIELD_AI_DIR=/path/to/lyrashield-ai \
  uv run python -m benchmarks.url_api_local_probe --output /path/to/new/receipt-directory
```

It verifies the fixture CA and hostname and checks denial of an untrusted CA,
wrong hostname, blocked path, method, host and port, an opaque CONNECT, and an
external redirect, plus invalid and revoked grants. The receipt binds the
fixture, source, runner, runtime, target host and port, public certificate,
scope digest and retained result bytes. The short-lived
fixture grant and signing secret are not retained, so its signature cannot be
independently reverified after the run.

This harness uses test-only resolver and port overrides, a diagnostic scanner
fetch adapter, and synthetic response bytes. It does not exercise the engine
TLS bridge, production DNS, verified-domain admission, a model route, or a
qualified image, and does not prove OS-level network isolation. No v3 URL/API
case or profile is measured by this diagnostic.
