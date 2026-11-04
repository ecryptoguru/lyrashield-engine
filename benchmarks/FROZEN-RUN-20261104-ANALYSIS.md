# Frozen deterministic run: attribution and coverage analysis

This documents offline run `20261104T133138Z`, engine source `c190d97fe6be2012ad2dd274b841958806062907`, product source `dd8a0cb84840d0397903a00fd3b795b1188ebc26`, and corpus v2. It is a trace of one synthetic development corpus, not a detection-quality claim or an independently adjudicated held-out evaluation. No engine/model or URL scan ran. The historical result files remain unchanged.

The run manifest identifies 78 executions: vulnerable and clean projections for each of 39 cases. The runner copies one complete fixture file for each projection. The deterministic entrypoint invokes secrets, SAST, IaC, agent-configuration and ML-supply-chain scanners; it excludes SCA. The recorded per-run coverage issues are empty, but this says those scanners reported no execution issue; it does not establish coverage of every case class.

| Case group | Observed vulnerable records | Interpretation for this harness and fixture |
| --- | --- | --- |
| AUTH-01–06 | none | The synthetic functions are not complete route/authorization flows. The selected SAST scanner's rules at the frozen product revision target cryptography/TLS/JWT patterns rather than these authorization semantics. This run does not measure authorization discovery. |
| INJECTION-01–06 | none | The fixture uses declared `db.query`/`run` stubs with no executable sink; the selected SAST rules do not implement these SQL/command-flow checks. This does not establish a detector failure against an executable vulnerable application. |
| DEPENDENCY-01–06 | none | The entries are fictional objects in a TypeScript file, not package manifests or locks; SCA is excluded. These cases are not a supported SCA measurement. |
| SECRET-01–06 | none | These are intentionally inert placeholders. The scanner's provider/generic patterns and false-positive hints deliberately exclude examples such as `placeholder` and `.invalid`, and several literals do not have the assignment syntax its patterns require. They are unsuitable as known-positive scanner fixtures; this is not proof about real secrets. |
| SVCKEY-01–02 | none | The fixture uses a public-env reference and inert placeholder strings. No selected rule in this run produced a finding; the product's URL scanner, which has a service-role-key test, was not invoked. Static and runtime behavior need separately qualified fixtures. |
| RLS-01–02 | none | The SAST scanner does not include `.sql` in its source extension set, and the selected harness has no RLS-specific scanner. The secrets scanner's file discovery is not RLS coverage. |
| IAC-01–11 | 47 records, 14 credited by the original scorer | All 33 originally unmatched records are findings for sibling cases in the same shared fixture file. They are repeated in each case projection and must not be counted as established false positives or independent extras. |

The IaC case locators themselves overlap. `IAC-05` accepts the broad prefix `iac-k8s` within three lines of line 13, so it also accepts the hostPath result at line 16; `IAC-06` accepts that same result. The original scorer credited the hostPath finding to both cases, even though the rule IDs and controls differ. Its duplicate calculation also counts additional same-scanner matches as duplicates without adjudicating whether they are distinct: `IAC-07` has three wildcard RBAC results at different lines. Neither the original reported match fraction nor duplicate rate is a validated precision, recall, or duplicate measure.

The attribution guard added alongside this note marks overlapping matches ambiguous, withholds case credit and sets the score `INCOMPLETE`. A diagnostic re-score on a temporary copy of the frozen input yielded 10 credited cases, 2 ambiguous records and 33 unmatched records; it is not a new scan or a replacement quality baseline. Correcting the locator requires a new versioned corpus and independent label review; do not edit the frozen v2 corpus or its retained results.

Original file SHA-256 values, measured before investigation:

- `findings.jsonl`: `1841ef5ec0fd8b0de44f1994e7a6be09e37b0d763ad2559ddf58656d948ce51c`
- `run-manifest.json`: `0f785e61c8d60dbe1d627e6a717e3852400d517d33743e5352549d53e5e71fdc`
- `results.json`: `383c577548685ed0d22dc98b31a230b38c5fed53de756e68483f9ab787c741d7`
- `RESULTS.md`: `31c538cad62d6956a9091ec01c775b908de1f0997f3106e2fd3faf217ff53480`

Next: define case-level supported scanner scope and independently adjudicated labels, use realistic safe positive/negative fixtures, and separate development and held-out cases. Qualify SCA, URL/API and engine/worker paths separately or explicitly exclude them. Retain exact source, fixture, profile and run receipts; the current checksum is not an authenticated attestation. No numeric quality threshold or public accuracy claim follows from this run.
