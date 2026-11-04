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

The optional `--diagnostic` mode lists each valid versioned effective Go
dependency with a document-level state. `matched` means exactly one matching
versioned SPDX package entry; `ambiguous` means multiple matches, a same-name
unversioned Go candidate, or a same-name package with no purl. The latter is
treated as unresolved even if its version field looks valid because its
ecosystem is unknown. The `unversioned_candidates` count includes these
untyped entries. `absent-but-unresolved` means no matching versioned or
recognized unresolved candidate was found. None of these states
establishes package coverage, binary ownership or image contents. A matching
entry may belong to another binary. For Go purls the diagnostic accepts only
the explicit `UNKNOWN` unversioned and `stdlib` forms encountered in the
retained document; malformed, unsupported or unversioned build identities still fail
without partial output. The strict default mode remains unchanged. Diagnostic
output always says `diagnostic-only`, and any ambiguous or absent state exits
nonzero; even an all-matched diagnostic does not qualify an artifact.

For an offline check on 2026-11-05, the caller supplied an amd64-labelled
historical BuildKit SPDX statement and a separately captured layer-local
gospider ELF. The Go tool reported 31 embedded versioned dependencies. The
diagnostic returned 22 single document-level matches, 9 ambiguous matches and
zero absent-but-unresolved entries, and exited 1. A separate direct recount of
the supplied statement produced the same counts. The ELF SHA-256 was
`52c810794b104cf0b61f57cbaff90e1f108c857e854c00a203fbd71112ffc1a3`, the
supplied SPDX bytes SHA-256 was
`a1a22fd2266e484dc91283fbbdfd94cff7854291bc5d38a0c058d3c8caa3f75f`, and the
operator-supplied Go tool SHA-256 was
`3f947495f00cb7f8088a5cfd694da8dc43869b33f5e7377b048fb18922ffb7e0`.
The ELF and Go metadata identified Linux amd64. This observation does not
authenticate the SPDX statement or establish that its subject, the retained
layer entry, a final overlay or a deployed image are the same artifact.

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
