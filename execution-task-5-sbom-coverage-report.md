# Task 5 — Image-bound bounded SBOM coverage report

## Status

Implementation and local evidence are complete in the isolated worktree at
`codex/sbom-image-coverage`. No workflow was dispatched, no registry or
production state was changed, no image was pulled or promoted for release, and
no release tag moved. The hosted two-platform coverage run remains outstanding,
and the publisher retains the unconditional promotion hold.

Resumed commits audited: `934f7103`, `10271224`, `1a79c249`.
Docs and classification completion commit: `42a8fbbb`.

## Delivered

- `934f7103 feat(sbom): bind rootfs inventory and Go relationships` — rootfs
  inventory binding in `scripts/check_sbom_inventory.py` (Debian, Python and npm
  identities from exported merged root filesystems), the new
  `scripts/sandbox_sbom_go.py` Go file/relationship comparison, and the four
  distro Go application identities in
  `containers/go-tools/distro/applications.cdx.json`. Added the rootfs-coverage,
  Go-relationship and distro-tool test suites.
- `10271224 feat(publish): add signed bounded SBOM coverage` — the 931-line
  `scripts/check_sandbox_sbom_coverage.py` platform/aggregate gate, and the
  coverage phase of `.github/workflows/publish-sandbox.yml`: checksum-pinned Go
  1.27.3 metadata inspector, per-platform create-not-run export with a
  900-second timeout and 8 GiB cap, byte-bound receipts, aggregate
  `lyrashield.sandbox.sbom-coverage.v1` predicate signed as
  `https://lyrashieldai.com/attestations/sandbox-sbom-coverage/v1`, explicit
  `publication`/`coverage` phases in `scripts/check_sandbox_attestations.py`,
  and the unconditional promotion hold retained after coverage verification.
- `1a79c249 fix(sbom): reject metadata exposed through directory aliases` — the
  inventory metadata probe now matches `package.json`/`METADATA` basenames, so a
  directory alias whose target contains reachable metadata can no longer be
  classified as ignored; added the alias regression tests.
- `42a8fbbb docs(sbom): record bounded coverage evidence and local link
  classification` — the bounded-coverage evidence doc
  (`docs/evidence/sandbox-sbom-bounded-coverage-2026-11-05.md`), the local
  classification record
  (`docs/evidence/sandbox-sbom-local-classification-2026-11-05.json`), the
  cross-link from the retained 2026-11-04 failure record, and the publishing
  documentation section.

## Audit against the task scope

- The gate claims a finite filesystem-to-SPDX scope only: Debian identities,
  declared Python and npm roots, and the exact 12 pinned Go application files.
  Everything else is explicitly out of claim and fail-closed.
- Every observed identity must have an exact typed purl in the per-platform
  SPDX; link policy version 2 permits an alias only when its final target
  exists and cannot expose unscanned metadata, and unknowns remain unresolved.
- Go binaries are bound by captured-byte SHA-256, ELF target, and
  `go version -m -json` module records, with per-file package relationship
  comparison against Syft `evident-by` slices.
- Attestation verification rejects coverage predicates in the publication phase
  and requires them in the coverage phase, binding run, attempt, revision,
  subject and exact expected predicate bytes.
- The gate is bounded package coverage, not image-wide SBOM completeness; the
  docs and evidence state this boundary explicitly.

## Tests and gates

Final raw gates against the committed tree (2026-11-06):

- `scripts/verify-controlled-derivative.sh` — upstream base fetch invariant,
  micro-fork footprint and reviewed patch digest, repo-wide `ruff check` and
  `ruff format --check`, full pytest suite (4,869 collected), mypy, and bandit.
- Focused SBOM coverage suite (13 files, coverage/rootfs/Go/attestation/
  publish/binding/BuildKit/Dockerfile): 356 passed.
- `ruff check` and `ruff format --check` on the changed scripts and tests.
- `actionlint .github/workflows/publish-sandbox.yml`.
- `tests/test_customer_branding.py`: an upstream-branding reference introduced
  by the report-side evidence wording was flagged and reworded; 9 passed.

Local parser smokes retained in the evidence doc: Docker create-not-run export
fixture, historical SPDX load (56,074 files), real-candidate amd64 export and
scan, and the 12-file Go relationship comparison.

## Classification result

On the local amd64 candidate `sha256:82332032…60263b87ddfbf0267b3e688`, the
prior run's 42 unresolved records are classified as 37 metadata-safe aliases
resolved by link policy version 2 and 5 hard failures: three unsafe directory
aliases and two duplicate-key npm manifests. The candidate still fails the
bounded gate, which is the correct fail-closed outcome until inputs or reviewed
scope change.

## Blockers and boundaries

- The hosted Ubuntu coverage job, both native rootfs exports, the real ORAS
  config fetch, and the GitHub attestation round trip are unexecuted; they
  require a hosted run and are outside this local task's authority.
- The Linux-only checksum-pinned Go metadata tool cannot execute on the macOS
  host, so hosted metadata execution is unverified locally.
- The unconditional promotion hold remains the authoritative release decision.
- No push, dispatch, credential use, promotion, or production access was
  performed.
