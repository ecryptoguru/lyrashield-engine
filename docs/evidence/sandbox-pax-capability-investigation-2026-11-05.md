# PAX capability metadata: offline investigation

The current virtual reconstructor and single-layer catalog **reject**
`SCHILY.xattr.security.capability`; this document and its synthetic tests do
not change that behavior. One incomplete historical stream attempt reported
that key in a parser prefix, but did not verify the full stream and did not
establish that this key caused its rejection or identify its entry. No actual
capability value was retained. The release hold remains in place.

A later, separately retained full-byte rejection drain reported matching the
compressed descriptor and uncompressed DiffID with fetch exit zero. In its
parser prefix it observed one `SCHILY.xattr.security.capability` key, along
with other allowed key names; the worker reported only the broader fixed reason
`unsupported-pax-key`. The receipt does not bind that key to the rejected
record, disclose its value, or enumerate later PAX headers. The source bytes
were discarded; the linkage is a local process receipt, not an independent
replay. Remaining tar framing, final overlay and release qualification remain
unverified.

The [OCI image layer specification](https://github.com/opencontainers/image-spec/blob/main/layer.md) lists extended attributes among supported
file attributes. The locally installed Go 1.26.5 [`archive/tar` parser](https://go.dev/src/archive/tar/strconv.go) and [tests](https://go.dev/src/archive/tar/strconv_test.go)
represent `SCHILY.xattr.*` values as PAX record values and explicitly tests a
value containing NUL; its parser treats the record's declared length as bytes.
These are implementation observations, not a conclusion about the encoding or
meaning of the historical value. Synthetic Python 3.13 tests in
`tests/test_pax_xattr_rejection_evidence.py` show that one constructed value
containing NUL, non-UTF-8 bytes, newline and `=` round-trips through this local
`tarfile` reader using UTF-8 with `surrogateescape`; they also show that its
PAX dictionary keeps only the last of duplicate keys. This does not establish a
universal PAX encoding or Linux capability validity.

A possible future *diagnostic representation*, requiring separate design and
security review before implementation, would:

- Parse byte-counted PAX framing before text conversion, reject malformed or
  noncanonical lengths and duplicate/conflicting names, reject global/stacked
  headers and unsupported xattr encodings, and associate a local attribute with
  exactly its following entry. Python `tarfile.pax_headers` alone is not a
  duplicate-preserving source of truth.
- Preserve the exact xattr name and value bytes in a bounded binary field,
  including absence versus empty value; never decode, normalize, print or
  apply the value with `setxattr`, execute image files, or grant privileges.
  A proposed prototype ceiling is the existing 16 KiB local PAX header cap,
  plus an independently enforced aggregate xattr-byte budget and existing
  entry/database/disk limits; exact value and aggregate limits need review.
- Treat hardlinks as shared inode metadata: reject xattrs on unsupported entry
  types and ambiguous or conflicting hardlink metadata until a reviewed model
  handles identity, replacement, whiteout and cross-layer semantics. Do not
  guess whether a later layer merges, replaces, clears or preserves an xattr.
- Authenticate the ordered descriptor/DiffID stream before publishing any
  representation; fail closed on unknown PAX keys, encodings, duplicate names,
  malformed records, unresolved association, limits or uncertainty. Do not use
  a private diagnostic catalog as a release qualifier.

Before claiming faithful handling, compare binary fixtures against pinned Go,
libarchive and OCI runtime implementations on an isolated Linux host, covering
NUL/non-UTF-8/newline/equals, duplicate records, alternate xattr encodings,
empty/missing values, hardlink aliasing, whiteouts and later-layer replacement.
A separate reviewed Linux capability-format and namespace analysis is needed
before interpreting the bytes. This Mac-only synthetic work neither applies nor
validates a capability and has no runtime differential.

File capabilities are security-relevant filesystem metadata even if a package
inventory compares only names and versions. Silently dropping them cannot prove
faithful image reconstruction or a security posture, and a package-membership
comparison alone cannot prove capability correctness. Full per-platform SBOM
coverage still requires a complete, authenticated final-image view and all
other release gates; this proposal does not provide either.
