# LyraShield Engine documentation

This directory contains the engine operator/reference documentation and a small number of retained upstream reference pages. The authoritative current boundaries are:

1. the repository [README](../README.md) for supported execution and artifacts;
2. [UPGRADES.md](../UPGRADES.md) for ownership and upstream imports;
3. [CONTRIBUTING.md](../CONTRIBUTING.md) for changes and verification. Engine CI enforces Ruff, strict Mypy, Bandit, pytest, controlled-derivative policy, builds, sandbox, and worker-contract checks on every pull request.

Artifact persistence semantics are part of the worker contract: `run.json` is written for every lifecycle or usage/cost save, while larger report projections use a durable revision and are rewritten only when report content changes. Resume restores that revision, and concurrent in-process saves are serialized. See the repository [README](../README.md#worker-artifact-contract) and the [upgrade ledger](../UPGRADES.md#artifact-persistence-optimization-2026-08-24). This reduces redundant local work without claiming a fixed scan-latency or model-cost improvement.

The local viewer uses its process-session capability to authorize run history; email verification applies to report delivery, not local history access. On narrow screens, use **Past runs** and **Back to current run**. The run selector identifies stored directories while displaying friendly run/target names. Agent transcript dialogs support keyboard focus containment and restore focus when closed.

The published navigation in `docs.json` includes supported LyraShield paths. Unsupported inherited providers are listed in [provider overview](llm-providers/overview.mdx).

If previewing locally with Mintlify, run it from this directory. The docs site is not itself a deployment or product-availability claim.
