# Private OCI layer spool prototype

This offline prototype stages **one opaque layer**, not an image filesystem. It
checks the caller-supplied compressed descriptor and uncompressed DiffID against
the same stream it writes, checks tar framing, and only then publishes a private
`verified.tar`. The caller must independently authenticate the descriptor and
DiffID, close the returned handle, and dispose of its own private child directory.
No promotion or release decision consumes this prototype.

The private root must already be a trusted, caller-owned directory with mode
0700. A randomly named child and mode-0600 provisional file are created under
directory file descriptors; archive member paths are never used as host paths.
On handled failures, cleanup attempts to remove only this invocation's files and
child. Publication uses an exclusive hard link after stream verification and
framing checks. A 4 GiB uncompressed limit, one million headers, a 900 second
processing deadline and a 2 GiB free-space reserve apply. The deadline cannot
interrupt a blocked read, and other processes can consume disk after a free-space
check. Host, caller, and concurrent processes with the same OS identity must be
trusted. Filesystem errors can prevent cleanup; crashes or power loss may leave
provisional files, and there is no crash recovery or durability guarantee.

Framing validation is not OCI changeset validation: members can contain unsafe
paths and unsupported entry types. It does not apply or resolve whiteouts, opaque
directories, hardlinks, symlinks, metadata, or layer ordering. A returned spool
must not be extracted by a general-purpose tar tool or treated as a final image,
safe overlay, SBOM completeness proof, or release qualification. A complete
reconstructor needs independently reviewed path and link semantics, atomic
multi-layer state, bounded storage and recovery, authenticated ordered inputs,
and negative tests for those boundaries.

Previously retained historical receipts report 61 layers and approximately
4.46 GB uncompressed per native image; the largest individual layers are about
2.26 GB (amd64) and 2.29 GB (arm64). The existing virtual reconstructor has a
128 MiB per-layer limit. A synthetic compressed 129 MiB layer exercises this
prototype beyond that limit; it does not establish that either historical image
can be reconstructed. No historical layer is fetched or processed by these tests.
