# Private, single-layer catalog prototype

`scripts/index_verified_oci_changeset.py` builds an **unapplied catalog of one
uncompressed tar stream**. It reads a seekable stream from offset zero, checks
its complete framing and SHA-256 DiffID, and only then publishes an SQLite
catalog in a private task-owned directory. Regular-file records point to byte
offsets in that same uncompressed stream; contents are not copied or extracted
onto host paths. Archive paths and link targets are SQL data, never host paths.
The source remains caller-owned. The catalog records normalized paths, types,
metadata, link targets and whiteout markers; recording a marker does not apply
it or resolve a link. The caller must independently authenticate the expected
DiffID's index/manifest/config binding and must reverify the exact source bytes
before using an extent. A catalog cannot authenticate a later, mutable source.

The prototype validates the restricted in-memory reconstructor's framing and
local PAX subset, rejects duplicate or unsafe normalized paths and malformed
whiteout markers, and constrains link syntax. A narrow canonical absolute symlink target is stored as inert image-namespace text; it is never followed on the host or resolved by this catalog. It deliberately permits unresolved
parents and hardlink targets because earlier layers are not available here.
It does not apply layer ordering, resolve cross-layer links, validate symlink
ancestors against a merged tree, establish filesystem metadata parity, inspect
packages, or compare an SBOM. No release workflow uses it. An actual overlay
requires a separate reviewed transactional state machine with those checks and
bounded lifecycle/recovery before any consumer can use this catalog for an image.

Limits are 4 GiB per uncompressed layer, 100,000 entries, 16 MiB total staged
path and link-target bytes, 128 MiB SQLite pages, a 900-second processing
deadline, and a sampled 2 GiB free-space reserve. SQLite and Python caches,
objects and filesystem allocation add overhead. The timer cannot interrupt all
blocked I/O, and other processes can consume disk between reserve checks. The
private root, host, and same-identity processes are trusted; macOS ACL absence
is checked and other platforms fail closed through the shared spool policy.
SQLite uses a generated private filename and no journal; handled failures try
to remove only their own files. Crashes or filesystem errors may leave private
provisional artifacts and there is no crash recovery or durability claim.

The tests use synthetic layers, including a sparse 129 MiB tar member, and do
not demonstrate compatibility with the historical layer or production image.
The existing in-memory layer limit and unconditional promotion hold stay in place.

A separate streaming experiment, `scripts/index_verified_oci_stream.py`, feeds
bounded decompressed chunks through a pipe into the catalog without retaining
the layer tar. The catalog stays under a private provisional directory while
the compressed descriptor and uncompressed DiffID are checked. Its caller gets
a success report only after the catalog finishes and the fetch process exits
zero. An externally supervised process-group wall timeout is required: a blocked
I/O operation or worker can outlive the function's bounded waits, and a crash or
stuck worker can leave its task-owned private directory for inspection. The
caller must never treat a residual catalog or a child exit alone as success.
Without retained tar bytes, catalog offsets cannot be consumed unless the exact
uncompressed source is obtained and fully reverified again. This experiment is
not an overlay or release qualification and is not connected to production.

If the catalog worker stops early and the pipe writer receives a broken pipe,
the streaming wrapper reports a fixed, allowlisted worker-error category once
the worker has stopped. Unknown errors receive a generic category; archive or
customer content from exception messages is not emitted. A category from an
incomplete stream is diagnostic only and does not authenticate the input or
establish the cause of any prior attempt whose worker error was not retained.

A separate unwired diagnostic, `scripts/verify_oci_rejection_drain.py`, can
continue consuming the same bounded compressed stream after the catalog rejects
its prefix. It exposes only an allowlisted worker-error category after the full
compressed descriptor and uncompressed DiffID match and the fetch process exits
zero. It does not preserve a catalog or input bytes and never treats rejection
as acceptance. Once the consumer rejects, the remainder is not parsed as tar,
so the result does not establish full archive framing or overlay validity.
A caller must independently authenticate the expected descriptor/DiffID chain
and use an external process-group wall deadline; the existing trusted-host,
sampled-reserve, possible residual and blocked-I/O limits apply.

For rejected catalog entries, the fixed unsafe-path category may additionally
identify the member kind or link-target role and whether the existing policy
rejected an absolute path, backslash, NUL, or multiple conditions. It never
includes path or target text and does not relax that policy. PAX validation or
other parsing errors can still produce a generic category. Even a category
observed over verified layer bytes describes this implementation's policy, not
proof that the archive is malicious or incompatible with every OCI runtime.
