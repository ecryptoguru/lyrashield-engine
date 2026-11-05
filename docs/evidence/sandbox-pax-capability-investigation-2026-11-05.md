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

A broader future *diagnostic representation*, requiring separate design and
security review beyond the deliberately narrower probe below, would:

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


## Unwired synthetic byte probe

`scripts/probe_pax_capability.py` is a separate, deliberately restrictive
in-memory experiment. It accepts exactly one canonical local PAX record with
the literal key `SCHILY.xattr.security.capability`, immediately followed by a
regular file. It retains its nonempty value as opaque bytes, associates it
with the normalized member name, header offset and file size, and returns the
observations only after complete tar framing and a matching caller-supplied
uncompressed DiffID. It does not authenticate that supplied DiffID, the
compressed descriptor, or the producer exit. A caller must establish those
bindings independently. Observation representations omit names and values, but
callers must treat returned fields as potentially sensitive and not log them.

The probe rejects all other PAX keys and multiple records, global or stacked
headers, empty values, links, unsupported types, whiteouts, duplicate names
and invalid paths. It enforces fixed per-header, value, aggregate, entry, path,
stream and elapsed-time limits; the time limit cannot interrupt blocked I/O,
which requires an external wall-clock supervisor. No files or attributes are
created, extracted, interpreted or applied. These rules intentionally exclude
the observed historical layer; no real layer has been processed by the probe.
This is a raw record observation, not a faithful final filesystem model, OCI
runtime differential, capability validity check, SBOM coverage check, or
release qualifier. The existing catalog and reconstructor continue rejecting
this PAX key.

## Isolated Linux parser comparison

The unwired `scripts/probe_linux_pax_differential.py` harness compares fixed
synthetic records with a cached Linux/arm64 Go `archive/tar` reader. It never
requests a download or extracts an archive; it does not call `setxattr`, create
capability metadata, use real image bytes, or mount or inspect host filesystem
contents as experiment input. It checks the local socket and receipt path, and
Docker reads local configuration. The harness requires a particular cached image
digest and the local Docker Desktop Unix socket, and
creates a labelled task-owned container with no network, no bind mounts, a
non-root identity, read-only root, dropped capabilities and bounded resources.
The inspected PID, IPC, UTS and user namespace modes reject host and shared
container settings. Docker default or private settings are accepted; IPC also
permits Docker `shareable` or `none`. Go compiles a fixed synthetic program in
a container tmpfs. The harness pins the local Unix socket on every Docker
command, verifies isolation before starting, and uses the verified immutable
container ID for starting and removal. Before creation it records a unique
name and ownership label in an owner-only receipt directory. Unconfirmed
creation outcomes remain unresolved even when the name is initially absent,
because the daemon could create it later. Daemon failure, client interruption
or host crash may leave a container that requires reconciliation against that
identity.

After independent safety review, one local run reported success on the fixed
synthetic cases: Go `archive/tar` associated a binary PAX value with its
following regular member and retained the last value for a duplicate key. The
separate restrictive probe rejected the duplicate. The parent receipt records
exit zero, no timeout and empty stderr; independent read-only listings found no
remaining task-owned container. The receipt, identity and scoped observation
note are in private evidence directory `linux-pax-differential-uepa1z5r` under
`sbom-registry-evidence-20261105`; the parent receipt SHA-256 is
`1c519552e1c86c957c66d34a6dafd0effcb768fdc7eb31f6180c5fa185ff7133`. The
source head was `4745fbfd90d125d2bddced9c32924e8fa0469f5c`, and the harness
SHA-256 was `ca850f242d60c3457fb4598205f4a091754aee85a7ce0e2539b3036335f3997a`.
The original stdout was hashed and discarded, then the fixed success line was
reconstructed and checked against that hash. Individual Docker inspection
transcripts were not retained, so the result is local process-receipt evidence,
not an independent attestation.

This compares Linux userspace parser observations only. It does not exercise
OCI layer application, Linux capability interpretation or enforcement,
hardlink/whiteout semantics, or runtime parity. It does not change catalog
rejection, release gates or SBOM qualification.

## Unwired raw capability header catalog

`scripts/catalog_pax_capability_headers.py` is a separate in-memory prototype
for one uncompressed layer. For each supported local capability record it
preserves the complete exact PAX payload and capability value bytes, associates
them with the immediately following regular-file or symlink header, and stores
the PAX and member header offsets plus effective PAX `path` and symlink
`linkpath` as inert text. Values and names may be sensitive and are omitted
from object representations; callers must not log returned fields. It accepts
only `path`, `linkpath` and `SCHILY.xattr.security.capability` local records,
rejects duplicates and unknown keys, and rejects capability records on
hardlinks, directories and whiteouts. It supports other allowed ordinary member
types only as raw archive observations; it does not infer inode aliases or
propagate attributes through hardlinks, whiteouts, layer replacement or symlink
resolution. In particular, a missing observation is not proof of absent final
filesystem metadata.

The catalog limits each PAX payload to 16 KiB, each capability value to 4 KiB,
retained PAX payloads to 4 MiB, observations to 1,024, entries to 100,000,
aggregate path and target text to 16 MiB, and uncompressed input to 4 GiB. It
checks complete tar framing and the caller-supplied DiffID before returning; a
caller must separately authenticate the descriptor and DiffID, producer exit,
and enforce a wall timeout for blocking input. The prototype does not write or
apply xattrs or extract archive entries. It is not wired into the existing OCI
catalog, stream verifier, image promotion or release flow, and its synthetic
fixtures do not establish Linux xattr interpretation, OCI runtime parity,
complete overlay semantics, image authenticity or SBOM completeness.

## Unwired aggregate-only capability stream

`scripts/verify_pax_capability_stream.py` feeds the bounded raw-header reader
synchronously from the compressed descriptor and DiffID verifier. The input
bytes and capability records stay in memory; the helper does not create an
archive spool, database, extracted file or host xattr. It returns fixed counts
of regular-file and symlink capability headers only after the verifier accepts
the complete compressed stream and DiffID, the tar reader accepts complete
framing, and the fetch exits successfully. It requires an owner-only ACL-free
private directory for a continuously checked free-space reserve. Unsupported
records, validation failures, fetch failures and cleanup errors produce an
incomplete result without counts or archive-derived error text.
The helper also permits an explicit `linux_literal_paths=True` option, which
adds a `linux-literal` path-policy marker to successful aggregate results. The
caller must authenticate the Linux platform before opting in; the marker is not
proof of that authentication. The default remains the strict path policy.

An opt-in local diagnostic can attach a fixed, allowlisted parser-rejection
category to an incomplete result. It is explicitly marked as an unverified
prefix observation: the compressed descriptor, DiffID, remaining tar framing
and fetch exit may not have been checked, and later failures may also exist.
It returns no archive paths, values or counts; cleanup failure suppresses the
category. A caller must emit only the fixed fields and must not inspect or
serialize exception contexts or traceback locals, which can retain input data.
It cannot recover the cause of an earlier incomplete attempt.
Known parser messages can be grouped into fixed member/link policy, PAX value
or encoding, parser limit and tar framing labels; unknown messages fall back to
`parser-rejected`. A caller that publishes these labels must independently
allowlist them and keep the result explicitly unverified and incomplete.
The member/link category also exposes a fixed, allowlisted reason and a role
only as specifically as the parser error permits; ambiguous cases report
`unknown` or `member-or-hardlink`. These fields likewise cannot identify the
path, prove a layer's authenticity or reclassify an older receipt. Callers must
independently allowlist the fields before publishing them.

This helper does not authenticate the caller-supplied descriptor or DiffID;
the caller must establish those bindings and supervise the fetch process group
with a wall deadline because blocked input cannot be interrupted by the local
deadline. Counts describe this restricted parser's headers in one layer and do
not establish a final filesystem, capability interpretation, OCI runtime
semantics, image qualification or SBOM completeness. It remains unwired from
promotion and release paths.

## Unwired full-byte rejection diagnostic

`scripts/diagnose_pax_capability_rejection.py` can report a fixed role and
syntax for a parser's first `unsafe path` rejection. It stops parsing at that
point, drains the same bounded stream without storing it, and reports only
after the compressed descriptor, DiffID, fetch exit and cleanup succeed. It
does not validate remaining tar framing, establish image or SBOM completeness,
or accept the rejected archive. The caller must authenticate the expected
descriptor and DiffID and enforce a process-group deadline for blocked reads.
The fixed result contains no path, target, package, count or source payload.
The helper is unwired and does not reclassify earlier unverified receipts.

An additional unwired full-drain outcome helper can report a fixed first
parser-rejection category, an EOF framing rejection, or acceptance by this
restricted parser. It returns only after descriptor bytes, DiffID and fetch
exit pass and cleanup succeeds. After a feed rejection it stops parsing and
does not claim remaining tar framing; an accepted outcome requires complete
framing. It retains no archive names, values, counts or payloads in its
result. Caller authentication of the descriptor, DiffID and selected Linux
platform, plus external blocked-read supervision, remain required. These
outcomes do not establish final image state, SBOM coverage or release readiness.

## Opt-in Linux literal-path prototype

The in-memory `VirtualRoot` and raw capability `HeaderReader` offer an explicit
`linux_literal_paths=True` option for synthetic evaluation. It preserves a
backslash as a literal character in member paths and hardlink targets; it does
not convert it to a separator. Default callers still reject such paths, and
symlink targets retain their existing restrictions. The caller must establish
that the target is Linux before selecting this policy; the option itself does
not authenticate the platform. This prototype does not apply entries to a
host filesystem and must not be used as a cross-platform path parser.

Synthetic tests cover raw and PAX paths, literal versus slash-separated
identities, duplicates, whiteouts, hardlinks and symlink ancestors. These tests
do not establish OCI runtime parity, final overlay state, complete package
coverage or a release qualification. The disk-backed OCI catalog and all
promotion and release paths retain their existing strict policy; the aggregate
stream remains strict unless a caller explicitly selects the Linux option.

The full-byte rejection diagnostic also has an explicit Linux-literal path
option, disabled by default. The caller must first bind that choice to
independently authenticated Linux platform metadata; the helper does not do so.
It treats backslashes in member and hardlink names as inert Linux filename
characters, never as host paths. Symlink-target restrictions remain unchanged.
The fixed rejection classifier follows the same selected policy, so an
accepted backslash in a member name cannot mask a later rejected symlink or
hardlink target. This diagnostic still stops parsing at its first rejection;
full-byte verification is not tar framing, final-overlay or release evidence.
