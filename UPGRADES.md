# LyraShield patch ledger

This fork stays deliberately thin. Keep these compatibility patches while
syncing upstream:

- `lyrashield_adapter`: compatibility adapter for LyraShield invocation.
- Telemetry defaults: LyraShield-safe telemetry behavior by default.
- Pydantic compatibility: fixes required by the supported runtime.
- Pre-Docker validation: validate inputs before container setup.
- Per-instance binds: avoid shared mutable configuration between scans.
- Worker output compatibility: preserve the worker's expected result format.
- Apache attribution banners: retain the one-line LyraShield modification notice
  in every fork-modified `strix/` source file.
- Upstream formatter compatibility: retain Ruff's mechanical formatting in
  `strix/tools/reporting/tool.py` and `tests/test_runner_root_prompt.py` until
  upstream contains the same formatting.
- Upstream strict-typing compatibility: retain the local-variable narrowing in
  `strix/skills/__init__.py` and dependency ecosystem normalization in
  `strix/tools/reporting/tool.py` until upstream contains equivalent fixes.

## Current upstream release

`v1.1.0`

The release tag is the latest stable Strix release incorporated by LyraShield.
The base below may be a later upstream commit when a reviewed post-release sync
has already been incorporated.

## Current upstream base

`7d5a67d234bd3faef34d22be8c6f5a9607de41a3`

`scripts/check-upstream.sh` remains a diagnostic for changes on upstream
`main`. Release imports use `scripts/sync-upstream-release.sh <tag>`, which
compares immutable file trees and therefore does not require linear ancestry.

## Automated review path

`.github/workflows/upstream-sync.yml` checks the latest stable Strix release
daily at 03:23 UTC and can also be started manually with a specific stable tag.
It applies the upstream tree delta to an
`automation/upstream-<tag>-<short-sha>` branch, regenerates the dependency lock,
and opens a ready pull request. Candidate upstream code is never executed in
this write-enabled job.

The separate read-only `Engine CI / verify` pull-request check proves the source
gate, Python package, native binary, sandbox runtime, and public
`ecryptoguru/lyrashield-ai` worker contract. The sync PR requests review from
`@ecryptoguru` and enables squash auto-merge. Approval is visible on the PR in
the right-side **Reviewers** panel and through **Files changed → Review
changes**. GitHub merges only after one approval and the required check is
green. Neither workflow deploys the engine or application.

If tree reconciliation conflicts, no branch is pushed. The workflow uploads
the generated patch and conflicting paths, then creates or updates one issue
labelled `upstream-sync`. Resolve that release through a reviewed PR; never add
automatic conflict resolution to the scheduled job.
