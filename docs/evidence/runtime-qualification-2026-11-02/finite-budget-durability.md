# Finite-budget durability boundary

A finite run persists its admission before a supported physical provider POST.
An accepted request with no known charge keeps a pending admission across process
termination and fresh-process resume. A decoded known charge updates verified
usage and removes its exact pending ID in one financial snapshot before report
projections or awaited auxiliary cleanup. An increase in the limit does not clear
pending charges. Paid resume with pending charges is denied; read-only receipt
and report viewing remains available.

The authority is the existing raw `run.json`, plus a private immutable
`.finite-budget-activated` file in the same owned run directory. The activation
file identifies the run and a random epoch, and holds the process owner lock.
A missing, corrupt or foreign half of an activated pair cannot be treated as a
legacy run. Neither file contains credentials or provider response bodies.
Removing both files or destroying the workspace destroys this local authority;
this is not tamper-proof remote billing storage.

`run.json` adds `_finite_budget_guard` with this bounded private format:

| Field | Meaning |
| --- | --- |
| `v`, `run_id`, `epoch` | Private format 1, same public run ID, 32 hex character activation epoch. |
| `revision`, `next_attempt` | Monotone signed 63 bit counters used for financial compare-and-swap and `epoch:counter` attempt identities. |
| `limit_units`, `known_floor_units` | Nonnegative integer USD units of `10^-10`; quotes round up and limits round down. The known floor remains separate from the verified public token ledger. |
| `usage_sha256` | Hash of the protected public `llm_usage` and `web_search_usage` fields. |
| `pending` | At most 64 exact `{id, quote_units, kind}` entries; kind is `llm` or `search`. |

The private guard is limited to 16 KiB and the complete financial snapshot to
1 MiB, matching the existing worker raw receipt read bound. Invalid numbers,
duplicate JSON keys, noncanonical IDs, unsupported fields, exhausted counters,
stale writers and failed required barriers deny further paid admission. These
bounds never justify deleting an unknown charge. Ordinary report writers use
financial CAS; finding and pending HTTP evidence rollback restore projections
while merging current protected usage, guard, and monotone receipt counters.
The main receipt initializer follows the same preservation path.

Interactive finite preflight owns the selected fresh or resumed run immediately.
Known probe usage is persisted before return to the UI. CLI and TUI reuse that
owner and do not replay `warm_up_usages`. An omitted limit restores the saved
limit; an ordinary option can tighten it, and cannot implicitly widen it. An
explicit interactive budget increase is a separate journal update. Legacy schema
1.0/1.1 receipts with neither private field nor activation file retain their
existing read/write behavior and version. Activation does not invent unknown
historical charges.

On POSIX, the implementation verifies directory handles, rejects symlinks and
unsafe ownership/permissions, uses exclusive private regular files, keeps the
owner lock stable, and requires file flush plus directory fsync around atomic
replacement. A failure poisons that process owner. This does not qualify power
loss guarantees for every remote or removable filesystem.

The Windows backend preserves native finite-run capability with qualified
Win32 handles: no reparse traversal, held directory handles, owner/ACL checks,
private creation, `LockFileEx`, file flush and atomic `ReplaceFileW` document
replacement. Ownership accepts the current token user or that process's
Administrators default owner, while rejecting unprivileged shared group owners;
Windows assigns new objects their token's
[default owner](https://learn.microsoft.com/en-us/windows/win32/secauthz/owner-of-a-new-object). Its intended guarantee is process termination/restart, not Windows
OS-crash or power-loss namespace ordering. Microsoft documents that
[`REPLACEFILE_WRITE_THROUGH` is unsupported](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-replacefilew).
The owner reads the locked activation range through its original handle because
[another handle cannot access that exclusive range](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-lockfileex).
Native Windows kill/restart, lock, reparse and stale-writer execution remains a
separate qualification gate; macOS execution does not prove Windows behavior.

The additive field is ignored by the actual pinned consumer `86537799` and
current consumer `90e24eb9` parsers for schema 1.0, 1.1 and 1.2 (six offline
compatibility controls). Their normalized records are not this journal's
financial authority and must never be used to reconstruct a paid resume.
Worker workspace replacement, retries and stalled delivery require their own
atomic lifetime execution fence. Local journal tests do not qualify that product
boundary, a provider's invoice, or a live total-dollar canary.

Offline regression coverage uses actual owned models and loopback HTTP: lost
acknowledgements, a killed child after server acceptance, fresh-process denial,
concurrent owner exclusion, corrupt/missing activation pairs, flush failure,
stale projection CAS, known settlement before projection failure, pending HTTP
rollback interleaving, and exactly-once CLI/TUI handoff. Provider credentials,
external targets and paid provider traffic are not used.
