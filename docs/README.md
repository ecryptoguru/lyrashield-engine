# LyraShield Engine documentation

This directory contains the engine operator/reference documentation and a small number of retained upstream reference pages. The authoritative current boundaries are:

1. the repository [README](../README.md) for supported execution and artifacts;
2. [UPGRADES.md](../UPGRADES.md) for ownership and upstream imports;
3. [CONTRIBUTING.md](../CONTRIBUTING.md) for changes and verification. Engine CI enforces Ruff, Mypy, Bandit, pytest, controlled-derivative policy, builds, sandbox, and worker-contract checks on every pull request. Repository-wide Pyright remains an explicit compatibility check; merged revision `944a84f` reports 0 errors and 0 warnings.

Artifact persistence semantics are part of the worker contract: `run.json` is written for every lifecycle or usage/cost save, while larger report projections use a durable revision and are rewritten only when report content changes. Resume restores that revision, and concurrent in-process saves are serialized. See the repository [README](../README.md#worker-artifact-contract) and the [upgrade ledger](../UPGRADES.md#artifact-persistence-optimization-2026-08-24). This reduces redundant local work without claiming a fixed scan-latency or model-cost improvement.

The published navigation in `docs.json` includes only supported LyraShield paths. Unlinked provider and cloud pages are retained solely to make the inherited upstream history reviewable; each is marked unsupported. Do not use those pages to configure production.

If previewing locally with Mintlify, run it from this directory. The docs site is not itself a deployment or product-availability claim.
