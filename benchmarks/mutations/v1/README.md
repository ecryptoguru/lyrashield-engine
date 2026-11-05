# Critical mutation probes v1

The v1 probe set exercises nine security contracts named by the delivery plan:
authorization, workspace scope, gate identity, evidence scope, cleanup UNKNOWN,
billing cap/replay, cache identity, report signature, and analytics privacy.

Run the harness from a clean source checkout:

```sh
uv run python -m benchmarks.mutation_probe --output /tmp/evaluation-mutations.json
```

For each probe, the harness creates a detached disposable Git worktree. It
requires the selected test to pass in the unmodified copy, applies exactly one
source replacement, requires the same test to fail for that probe, restores
the source, verifies the restored SHA-256 equals the baseline hash, and reruns
the test successfully. The source checkout is never edited and must be clean
before the run begins.

The committed probe manifest contains the exact source text, replacement, test
node, and expected failing test identity. Probe output retains the command,
baseline and mutated output tails, all three hashes, runtime, and cleanup state.
A mutation is evidence of regression-test sensitivity only. It does not prove
deployment behavior, live tenant isolation, cryptographic key custody, or that
all equivalent bypasses are covered.

The report-signature probe exercises Ed25519 verification over retained
`results.json` bytes. The analytics probe verifies that exception type is sent
without private exception messages. The billing probe uses local transport test
doubles and makes no provider call.
