# LyraShield evaluation corpus v1

This private deterministic starter corpus contains 24 vulnerable/clean pairs across authorization, secrets, injection, and dependency handling, plus eight incomplete-run scenarios. The fixtures are synthetic and contain no working credentials or real vulnerable package coordinates.

`corpus.json` records the case class, required control, expected remediation, failure state, and metrics. Every pair carries the same case marker in its vulnerable and clean projection. `validate.py` checks the version, counts, uniqueness, required metadata, fixture presence, and fail-closed incomplete-scan expectations in ordinary CI.

The corpus validates fixture integrity and deterministic result handling. It does not measure model discovery quality by itself. Precision, recall, runtime, and cost require separately authorized bounded model runs whose exact engine revision, model route, receipts, and adjudication are retained. Aggregate quality or superiority claims require reviewed run receipts.
