# Reviewed sandbox dependency exceptions

The sandbox installs the complete hash-pinned `python-requirements.txt` with
`--no-deps`, applies two exact metadata exceptions, then requires `pip check`.
Dependency audits remain mandatory. Neither upstream tool's Python source is
modified. The patch validates the pinned distribution, the exact original
dependency field, and the original METADATA checksum/size in RECORD before any
write, then updates RECORD to describe the changed bytes.

- Dirsearch 0.5.0: the existing exception permits the tested PyOpenSSL 26.4.0.
- Semgrep 1.178.0: permit only `pyjwt[crypto]>=2.14.0,<2.15.0`, replacing its
  vulnerable `~=2.13.0` restriction. Keep Semgrep's original verified wheel and
  hashes. PyJWT 2.14.0 is pinned in both engine and sandbox locks; all other
  sandbox dependency versions and artifact hashes remain unchanged.

The Semgrep exception requires the real installed MCP verifier to accept a
valid RS256 token and reject forged/expired tokens and redirected JWKS. The
sandbox smoke script also verifies the unchanged CLI version and a real local
finding. `verify_semgrep_pyjwt.py` runs these checks without credentials or
provider traffic. A JWKS redirect raises a PyJWKClient error and does not accept
a token or contact the redirected destination.

To regenerate only PyJWT while retaining the existing output's other pins:

```sh
uv pip compile containers/requirements.in --generate-hashes --universal \
  --no-header --no-annotate --upgrade-package pyjwt \
  --overrides containers/pyjwt-override.txt \
  --output-file containers/python-requirements.txt
```

Preserve the hash-lock's explanatory header and inspect the resulting diff;
only PyJWT's version and artifact hashes should change. The resolver exception
is explicit and limited to that dependency; the post-patch `pip check` must
still enforce every installed dependency.

Remove the Semgrep exception only after an official release declares a fixed
PyJWT range and passes the same checks. Until then, rollback requires a tested
image retaining patched PyJWT. Do not restore vulnerable PyJWT or suppress an
audit to make the upstream restriction pass. If the compatibility checks fail,
keep release blocked for a reviewed alternative.
