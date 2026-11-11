# Sandbox bounded SBOM coverage gate

This patch implements a finite package-coverage gate for the two native sandbox children. It does not claim image-wide SBOM completeness. The unconditional promotion hold remains because no hosted run has supplied both-platform receipts and a signed coverage predicate.

## Trust chain and inputs

For each `amd64` and `arm64` child, the publisher:

1. reads the exact child digest from the verified qualification and signed per-platform SBOM predicate;
2. fetches and hashes the native manifest bytes, parses the exact config descriptor, fetches the config by digest, and validates the Linux platform and ordered root filesystem diff IDs;
3. pulls the exact child, creates an unstarted container with `docker create`, and requires the expected container ID, local image ID, platform, root filesystem layers, container image, created state, zero PID, and absent mounts to agree;
4. streams `docker export` under a 900-second timeout and an 8 GiB cap, then hashes the exact exported bytes and records both effective limits in the receipt;
5. reads the exact per-platform SPDX bytes from the verified SBOM artifact and requires the signed predicate root, child, config, size, digest, filename, platform, and document identity to agree;
6. streams one merged-rootfs pass for Debian, Python, npm, and the exact 12 pinned Go binaries; and
7. produces a canonical owner-only platform receipt only after every binding and inventory check succeeds.

The platform loop removes the container, local image, rootfs, and private binary captures before the next architecture. The successful evidence upload contains receipts and the aggregate predicate, not multi-gigabyte filesystems.

## Finite inventory scope

The observable package scope is:

- installed package identities in `var/lib/dpkg/status`;
- `*.dist-info/METADATA` directly under `usr/lib/python*/dist-packages`, `usr/local/lib/python*/dist-packages`, and `app/.venv/lib/python*/site-packages`;
- `package.json` records under `home/pentester/.npm-tools/node_modules`, `usr/share/nodejs`, and `usr/local/lib/node_modules`; and
- the exact eight supplement and four distro application files declared by `containers/go-tools/applications.json` and `containers/go-tools/distro/applications.cdx.json`.

Every observed Debian, Python, and npm identity must have a matching typed purl in the exact SPDX document.

Version 2 of the link policy resolves bounded symlink chains and classifies a non-metadata alias as ignored only when its final target exists and the target cannot expose unscanned Debian, Python, or npm metadata. Regular-file targets, directory targets with no reachable protected metadata, and aliases to metadata already parsed at its physical path are accepted. Links at a guarded root or ancestor, hardlinks in guarded scopes, aliases to unscanned metadata, directory targets containing unguarded nested links, unresolved or cyclic metadata links, duplicate critical metadata, and unsafe paths fail closed. Absolute symlink targets are resolved relative to the exported archive root. The receipt records the count and policy object `sandbox-bounded-package-link-policy` version `2`.

The claim excludes every file and ecosystem outside this list. In particular, it does not prove that Syft enumerated all files, source trees, downloaded binaries, vendored code, or package managers.

## Go file and relationship method

Each required binary must be one regular, bounded archive member. The gate captures its exact bytes without executing the image binary, requires one SPDX file at the installed path, requires one SHA-256 file checksum equal to the captured bytes, validates the ELF architecture, and invokes only the checksum-pinned host Go 1.27.3 metadata tool.

The per-file SPDX slice is accepted only when:

- the binary file has exactly one main package and one Go standard-library package linked through `relationshipType: OTHER` and Syft's exact `evident-by: ...` comment;
- `stdlib` has the canonical `pkg:golang/stdlib@<version>` identity and matches `GoVersion`;
- a normal build has `Main.Path` equal to the pinned module;
- a direct `command-line-arguments` build has exactly one expected-module/`(devel)` self record, with no other local main module; and
- every effective `Deps` replacement has exactly one linked canonical Go package with matching name, version, and purl, with no extra or duplicate linked versioned module.

The comparison is per file, so repeated package purls across different binaries do not create document-global ambiguity. The SPDX local main package remains `UNKNOWN`; its display version comes from the pinned repository manifest and is explicitly documented as an external source-version binding, not binary proof.

## Receipt, aggregate, and signature

Platform receipts use `lyrashield.sandbox.sbom-coverage.platform.v1` and are deterministic canonical JSON written with exclusive creation. The aggregate gate requires exactly one schema-exact `amd64` and one `arm64` receipt. It verifies every receipt against the qualification, signed SBOM predicate, expected image, trusted Go tool digest, Docker exporter identity, exact limits, ignored-link policy, and exact 12 name/module/version/path tuples. It emits `lyrashield.sandbox.sbom-coverage.v1` with receipt digests and the bound platform, container, rootfs, SPDX, Go, exporter, scope, application, and limitation evidence.

The aggregate is signed as `https://lyrashieldai.com/attestations/sandbox-sbom-coverage/v1`. Verification uses the fixed publisher workflow, signer and source revision, source ref, GitHub-hosted runner environment, run/attempt, exact subject, and exact expected predicate content before the evidence upload. Promotion remains held after verification.

## Verification performed locally

Final rerun on 2026-11-06 against the last commit (`fix(sbom): reject metadata exposed through directory aliases`):

- `uv run pytest -q` focused SBOM coverage suite (`test_sandbox_sbom_coverage.py`, `test_sandbox_rootfs_coverage.py`, `test_sandbox_sbom_go_relationships.py`, `test_sbom_inventory_oracle.py`, `test_sandbox_distro_go_tools.py`, `test_sandbox_attestation_verification.py`, `test_sandbox_native_publish.py`, `test_sandbox_sbom_binding.py`, `test_pax_xattr_rejection_evidence.py`): 225 passed. The expanded SBOM/publish set adding `test_buildkit_sbom_chain.py`, `test_go_sbom_coverage.py`, `test_sandbox_go_tools.py`, and `test_sandbox_dockerfile.py`: 356 passed.
- `uv run ruff check` and `uv run ruff format --check` on the changed scripts and tests: passed.
- `actionlint .github/workflows/publish-sandbox.yml`: passed.
- `scripts/verify-controlled-derivative.sh`: passed, including the reviewed upstream micro-fork patch digest and full project gates.
- Post-policy link classification of the prior run's 42 unresolved records on the same candidate: 37 resolved as metadata-safe aliases under policy version 2 (2,535 ignored links) and 5 remaining hard failures (three unsafe directory aliases plus the two duplicate-key npm manifests), recorded in [`sandbox-sbom-local-classification-2026-11-05.json`](sandbox-sbom-local-classification-2026-11-05.json). The candidate still fails the bounded gate, as documented below.

Run history retained from the interrupted session:
- Docker create-not-run fixture: a local amd64 scratch fixture remained `created`, not running, with PID 0; `docker export` produced a valid 8,192-byte tar and the strict reader accepted its framing.
- Historical SPDX parser run: 56,074 files, 4,850 packages, and 4,438 files with valid evident-by slices loaded successfully.
- Real local candidate parser smoke (`sha256:8233203294f63dee305842334263037acaf7e9e4f75297b87ddfbf0267b3e688`): unstarted Docker export streamed and scanned in 38.58 seconds. It reported 1 Debian, 191 Python, and 1,766 npm identities, 2,498 ignored links, and 42 unresolved records. Those 42 records include two npm manifests with duplicate JSON keys and guarded links that can affect package discovery. This is a fail-closed parser result, not a passing release input.
- Local Go relationship smoke: all 12 app files copied from the same unstarted candidate matched the retained historical SPDX file checksums and per-file relationship slices using a host Go metadata reader; the run completed in 5.47 seconds. The historical SBOM was not bound to the current image manifest, so this is parser and coincident-file evidence only.

## Remaining boundaries

No workflow was dispatched, no registry or production state was changed, and no release tags moved. The Linux Go 1.27.3 archive was downloaded and its Dockerfile SHA-256 was checked locally, but that Linux executable cannot run on the macOS host; the hosted Ubuntu job and both native rootfs exports remain unexecuted evidence gates. The workflow's real ORAS config fetch, GitHub attestation round trip, and upload have not been exercised by a hosted run.

The current local candidate would fail the bounded gate on its two duplicate-key npm manifests and guarded links. That is expected until the evidence inputs or reviewed scope are changed. Until a hosted run succeeds for both native children, the unconditional promotion hold remains the authoritative release decision.
