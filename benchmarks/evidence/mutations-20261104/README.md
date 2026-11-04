# Offline evidence-binding mutation experiment

This experiment exercises existing tests at engine revision `8e25464351c96985158df7cea100c2b3c1aa8338`. It ran on 2026-11-04 in an isolated worktree with Python 3.13.14 and pytest 9.1.1. The tests use temporary local files and a fake capture client; no provider, real target, shared database, or production state was involved. The source and test file hashes are retained in [source-sha256.txt](./source-sha256.txt).

The unmodified baseline and restored source each passed all eight selected cases. The three mutations were applied separately, with each prior mutation reversed before the next. Each selected assertion failed for the expected reason:

| Mutation | Test | Result |
| --- | --- | --- |
| [Accept foreign hosts](./foreign-host.diff.gz) | `test_foreign_host_remains_pending` | [Failed](./foreign-host.output.txt.gz): export became `exported` instead of `failed`. |
| [Omit run-ID binding](./foreign-run-id.diff.gz) | `test_forged_export_binding_never_promotes[run_id]` | [Failed](./foreign-run-id.output.txt.gz): the forged binding no longer raised. |
| [Omit finding-revision binding](./finding-revision.diff.gz) | `test_forged_export_binding_never_promotes[finding_revisions]` | [Failed](./finding-revision.output.txt.gz): the forged revision map no longer raised. |

The complete baseline and restored output is in [baseline.output.txt.gz](./baseline.output.txt.gz) and [restored.output.txt.gz](./restored.output.txt.gz). The diffs and raw outputs are losslessly gzip-compressed; read them with `gzip -dc`. The unmodified files were verified with `git diff --exit-code` after restoration. No mutation is part of the committed source.

To reproduce against the same clean revision, use a disposable worktree, decompress and apply exactly one linked diff (`gzip -dc <diff>.gz | git apply`), run its command below, and reverse that diff (`gzip -dc <diff>.gz | git apply -R`) before proceeding. The first command is also the baseline/restoration check. A mutation is detected only when its corresponding assertion fails for the stated reason; an import error or unrelated failure is not a detection.

```sh
python -m pytest tests/test_pending_http_evidence.py::test_foreign_host_remains_pending tests/test_pending_http_evidence.py::test_forged_export_binding_never_promotes -q
python -m pytest tests/test_pending_http_evidence.py::test_foreign_host_remains_pending -q --tb=short
python -m pytest 'tests/test_pending_http_evidence.py::test_forged_export_binding_never_promotes[run_id]' -q --tb=short
python -m pytest 'tests/test_pending_http_evidence.py::test_forged_export_binding_never_promotes[finding_revisions]' -q --tb=short
```

This is a narrow test-sensitivity check for three logical changes in one HTTP evidence path. It does not establish protection against all foreign evidence or prove tenant authorization, revision-cache invalidation, physical cleanup, actual proxy behavior, provider behavior, or deployment acceptance. Those remain separate evaluation and release gates.
