# Scoped Go dependency comparison prototype

`scripts/check_go_sbom_coverage.py` is an offline, non-release experiment. It
copies one caller-selected Linux ELF into a temporary file, hashes the captured
bytes and invokes an explicitly supplied **trusted host Go tool** with
`go version -m -json` on that copy. It never runs the inspected image binary.
The ELF machine field and Go build settings must both identify the requested
`amd64` or `arm64` Linux target. The process disables Go proxy, checksum database,
automatic toolchain downloads and workspaces; it limits time and output size.

The comparator requires each versioned dependency in the Go build information
to have a matching name, version and canonical `pkg:golang` package URL in the
supplied SPDX 2.3 document. If a dependency has a versioned module replacement,
the effective replacement is compared; local or otherwise unversioned
replacements fail as unresolved. Duplicate declarations, empty dependency
metadata, missing or mismatched entries, malformed JSON and unsupported target
information fail closed. Package IDs must be present and unique; reference
fields must be present, bounded and free of control characters; and a matching
dependency must have exactly one matching
SPDX package entry. Repeated purls can legitimately describe separate binaries;
they remain unresolved here because this prototype does not validate SPDX
binary-to-package relationships. A BuildKit in-toto v1 SPDX envelope is accepted
as a container only; this tool does **not** verify its signature or subject.
These checks do not constitute complete SPDX schema or reference validation.

The JSON result records the SHA-256 values of the supplied SPDX bytes, captured
binary and selected host Go tool. It compares document-level membership only;
it does not establish that SPDX relationships associate each package with the
binary. The operator must provide stable, trusted inputs and a trusted Go tool.
Hashes alone do not authenticate either input, prove that the binary came from
an OCI layer, or stop an attacker able to alter the host tool concurrently.
The embedded metadata itself is a claim in the binary, not independent proof of
source, checksums or all linked/vendored code.

The main application, Go standard library, unversioned modules, C libraries,
other binaries and other ecosystems are outside this slice. No result from this
tool establishes complete package coverage, architecture-wide qualification,
signature validity or permission to publish/promote an image. Actual image
filesystem reconstruction, digest binding, adversarial validation, independent
review and both native release checks remain open. The existing publication
hold remains unchanged.

Example, after independently obtaining a stable binary and SPDX document:

```sh
python3 scripts/check_go_sbom_coverage.py \
  --binary /path/to/captured-linux-go-binary --architecture amd64 \
  --spdx /path/to/spdx.json --go /absolute/path/to/trusted/go
```

This POSIX-only prototype accepts regular files, rejects final-component
symlinks for binary and SPDX inputs, caps the binary at 512 MiB, SPDX at 128 MiB,
Go output at 16 MiB and the inspector at 30 seconds. The operator-supplied Go
tool may itself be a symlink, as in common installations. The prototype does
not independently verify parent path components or protect against hostile
writers changing files while read. No
actual sandbox image, provider request, artifact publication or promotion was
performed by the synthetic tests.
