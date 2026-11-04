# Offline selective OCI layer capture prototype

The historical native manifests contain 61 gzip layers per architecture. The
largest measured amd64 layer was 857,707,366 compressed / 2,255,685,632
uncompressed bytes; the corresponding arm64 layer was 854,772,237 / 2,285,072,384
bytes. The existing virtual reconstructor caps each uncompressed layer at
128 MiB and cannot process those layers. These measured byte checks do not
establish filesystem semantics or complete package coverage.

`scripts/inspect_oci_layer_entry.py` is an **unwired single-layer experiment**.
It consumes the same stream as the existing descriptor/DiffID verifier, checks
restricted tar framing, and stages only one requested regular-file payload in
a temporary file. It returns that file to its caller only after the entire layer
has reached EOF, the compressed descriptor size and digest and uncompressed
DiffID have matched, and the tar framing has passed. The caller must close the
returned file. Provisional bytes are closed on any failure. No inspected image
binary is run, no full layer is stored, and no release workflow calls this code.

The result is explicitly **one entry in one layer**, not the final image file.
All symlink and hardlink entries, even unrelated ones, fail closed. Target or
ancestor whiteouts and opaque markers fail closed regardless of order. Unrelated
valid whiteouts can be present, but this experiment does not apply them. It also
rejects duplicate paths, non-directory target ancestors, PAX/GNU extensions,
special files, malformed whiteouts and unsupported tar encodings. These
deliberate restrictions mean real OCI-valid layers may be rejected; they do
not establish correct handling of general whiteout or link semantics.

Selected content is limited to 256 MiB, paths and entries use the existing
reconstructor's limits, and the temporary filesystem must have a 2 GiB reserve
plus the declared selected size before capture. The check cannot reserve space
against concurrent writers; an I/O failure aborts the attempt. Stream decoding
and hashing retain the existing 16 GiB per-layer bound. A monotonic 900-second
deadline is checked between decompression chunks and cannot interrupt blocked
OS I/O. Python objects, decompressor buffers and tar parsing have overhead.

Synthetic tests include an uncompressed 129 MiB layer produced from small
streaming chunks, valid small captures, descriptor/DiffID tampering, incomplete
tar, path ambiguity, whiteouts, links, storage reserve and cleanup on failure.
They neither exercise the 2.2 GB historical layers nor establish runtime parity.
The caller must independently authenticate the descriptor, native manifest,
config and expected DiffID; byte binding by itself is not provenance.

Full ordered-layer overlay application, directory replacement, links, whiteout
precedence, trusted on-disk staging, OCI and runtime differential testing,
image-to-SBOM relationships, package completeness and both platform release
acceptance remain open. This prototype must not be used as a promotion gate or
as proof that the captured bytes are the image's final file. The publication
hold remains in place. No historical layer payload, provider request or image
was fetched or changed for these synthetic tests.
