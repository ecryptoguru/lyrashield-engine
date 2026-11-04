# Evaluation corpus inventory

Inventory of the checked-in corpus at engine revision `afda0effd9d62b4aea664bf6c899c5e30b7566cb`, inspected on 2026-11-04. This is an inventory, not a quality score or an assertion that the labels have been independently adjudicated.

| Corpus | Paired cases | Declared failure scenarios | `corpus.json` SHA-256 |
| --- | ---: | ---: | --- |
| v1 | 24 | 8 | `7ea2f7e5e51c0ee2c8e2a6c58c46391350d925a622ca1db389b064a7ef241475` |
| v2 | 39 | 10 | `bf8cc1bed3cec211b427ca5c841dbae7689ac3d6881d9f8542e550de52304221` |

Each pair declares a vulnerable and clean projection, a required control, and an expected remediation. Several cases share fixture files: pair counts are not counts of independent applications. V1 has six cases each for authorization, secrets, injection, and dependency handling. V2 retains those 24 and adds two service-key, two row-level-security, and eleven infrastructure-as-code cases. The complete case IDs, controls, and failure expectations are in each version's `corpus.json`; the v1 README describes its fixtures as synthetic. The source, license, and independent review of all v2 labels still need explicit evidence before treating them as an independent evaluation set.

V2 declares `LIVE-01`, with expected missing-security-header and verbose-error findings, but its referenced `fixtures/vulnerable-web/Dockerfile` is absent at this revision. The current runner iterates paired cases, not `liveTargets`; a complete paired run therefore does not establish URL-mode coverage. Failure scenarios are declared expectations and are not themselves evidence of executed failure tests.

The offline deterministic harness invokes secrets, SAST, IaC, agent-configuration, and ML supply-chain scanners. It explicitly skips SCA; its scope is not a complete engine, URL/API, worker, or cache evaluation. The scorer reports case matches, clean-fixture findings, unmatched vulnerable-fixture findings, duplicates, and run status. These are not independently adjudicated precision and recall: unmatched findings remain unclassified, and the cases have not been established as a representative held-out set. A `COMPLETE` harness status is a consistency gate for the selected paired runs, not proof of broader coverage or an approved public claim. Version 3 checks record identity and counts and binds exact findings bytes to a digest in the manifest. That digest is not authenticated; coordinated edits to the findings and manifest are not detected.

Before reporting quality measures, retain version-bound labels and fixture provenance, separate development from held-out cases, independently adjudicate one-to-one matches and duplicates, and document unsupported and incomplete cases. Preserve the additional run, contract, receipt, and signoff rules in [CLAIMS.md](./CLAIMS.md). Paid engine benchmarks need separate explicit authorization.
