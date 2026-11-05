# LyraShield evaluation corpus v3

`corpus.json` is a development corpus for adjudication and scoring-contract
work. It retains the v2 cases and adds PHP authorization and frozen-advisory
Composer controls plus explicit identity/retest, stale-evidence, partial-result,
cleanup-unknown, URL/API and local-CLI scenarios.

The fixtures are synthetic and contain no customer, credential or production
data. Every case names the path profiles that could produce evidence for it.
No profile has a quality result yet: all five profiles are `NOT_MEASURED` in
[`paths.json`](../../profiles/v1/paths.json).

`adjudications.json` records the independent-review contract. Its current
status is `NOT_INDEPENDENTLY_REVIEWED`; no decisions are pre-populated. The
implementation author cannot satisfy independence. A reviewed record requires
at least two distinct reviewers who are not implementation authors, per-finding
rationale, and reviewer assignment on each decision.

`held-out.json` records a separate reviewer-only storage contract. Its current
status is `NOT_PROVIDED`; there are no held-out bytes or checksums to imply that
held-out evaluation happened. Claims validation fails closed until a held-out
contract supplies verified manifest, fixture and label checksums when a claim
requires that scope.

A `VERIFIED` held-out contract must also record `verification.reviewerId` and a
timezone-bearing `verification.reviewedAt`; checksums alone cannot establish
that an independent reviewer checked the retained bytes. Corpus provenance and
the adjudication review status must match.

`advisories/frozen.json` is synthetic offline SCA data. It is not a live
advisory feed and cannot support a live vulnerability claim.

Run the validator with:

```sh
uv run python -m benchmarks.corpus.v3.validate
```

The checksum fields in `corpus.json` bind this manifest to the adjudication,
held-out, advisory and path-profile documents. Edit a contract through its
reviewed source and deliberately update the expected checksum; never rewrite
historical results.
