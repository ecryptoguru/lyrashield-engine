# Reviewed sandbox dependency exceptions

The sandbox installs the complete hash-pinned `python-requirements.txt` with
`--no-deps`, applies exact reviewed metadata exceptions, then requires `pip check`.
Dependency audits remain mandatory. Neither upstream tool's Python source is
modified. The patch validates the pinned distribution, the exact original
dependency field, and the original METADATA checksum/size in RECORD before any
write, then updates RECORD to describe the changed bytes.

- Dirsearch 0.5.0: the existing exception permits the tested PyOpenSSL 26.4.0.
- Semgrep 1.178.0: permit only `pyjwt[crypto]>=2.15.1,<2.16.0`, replacing its
  vulnerable `~=2.13.0` restriction. Keep Semgrep's original verified wheel and
  hashes. PyJWT 2.15.1 is pinned in both engine and sandbox locks (CVE-2026-101918
  fix line); the verified Semgrep wheel and its source remain unchanged.
- Semgrep 1.178.0 runtime: MCP 1.30.0 fixes redirect/header and schema-reference
  issues. OpenTelemetry API/SDK/exporter 1.45.1 and matching instrumentation
  0.66b1 fix the vulnerable API line. These exact resolver overrides correspond
  to exact METADATA substitutions, validated together before writes.
- Independent security refresh: aiohttp 3.14.5, graphql-core 3.3.1, certifi
  2026.10.18, and setuptools 84.1.0. The graph is hash-pinned for both CPUs.

The Semgrep exception requires the real installed MCP verifier to accept a
valid RS256 token and reject forged/expired tokens and redirected JWKS. The
sandbox smoke script also verifies the unchanged CLI version and a real local
finding. `verify_semgrep_pyjwt.py` runs these checks without credentials or
provider traffic. A JWKS redirect raises a PyJWKClient error and does not accept
a token or contact the redirected destination.

To reproduce the sandbox graph independently from the engine SDK constraints:

```sh
uv --no-config pip compile containers/requirements.in --generate-hashes --universal \
  --no-header --no-annotate \
  --overrides containers/pyjwt-override.txt \
  --output-file containers/python-requirements.txt
```

Preserve the hash-lock's explanatory header and inspect the resulting diff;
only the explicitly reviewed security graph should change. The resolver exception
is explicit and limited to that dependency; the post-patch `pip check` must
still enforce every installed dependency.

The compatibility script also proves real requests/threading instrumentation,
parent context propagation, and a successful OTLP HTTP export to a loopback
fixture. The unchanged Semgrep CLI must produce exactly one expected JSON finding.
No provider credentials or external telemetry are used.

Remove the Semgrep exceptions only after an official release declares a fixed
PyJWT range and passes the same checks. Until then, rollback requires a tested
image retaining patched PyJWT. Do not restore vulnerable PyJWT or suppress an
audit to make the upstream restriction pass. If the compatibility checks fail,
keep release blocked for a reviewed alternative.

Brotli CVE-2026-111497: the signed Kali snapshot still serves `1.2.0-4+b1`
on amd64 and arm64. `install_brotli.sh` installs only Debian's fixed
`libbrotli1=1.2.0-4.1`, verifying an architecture-specific SHA256 before dpkg.
It skips an already-fixed archive package and fails on unsupported CPUs.
`verify_brotli.py` checks the package floor and performs a real library decode
in each sandbox smoke run. No Debian apt repository or general overlay is added.
