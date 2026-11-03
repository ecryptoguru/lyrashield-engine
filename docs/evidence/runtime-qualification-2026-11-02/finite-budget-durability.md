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
| `observations` (optional) | At most 64 private `{key, cost_units, settled}` callback receipts. `key` hashes the run-scoped provider response ID. Old guards without this field remain readable. Capacity exhaustion fails closed; identities are never silently discarded. |

The private guard is limited to 16 KiB and the complete financial snapshot to
1 MiB, matching the existing worker raw receipt read bound. Invalid numbers,
duplicate JSON keys, noncanonical IDs, unsupported fields, exhausted counters,
stale writers and failed required barriers deny further paid admission. These
bounds never justify deleting an unknown charge. Ordinary report writers use
financial CAS; finding and pending HTTP evidence rollback restore projections
while merging current protected usage, guard, and monotone receipt counters.
The main receipt initializer follows the same preservation path. A stable
`.finite-budget-transition` native lock serializes first activation with the
complete legacy write, raw restore, or unlink. Read-only classification does not
apply finite ownership rules to an unactivated legacy write (including normal
0775 directories). Missing finite directories are created through verified
no-follow parents, before hydration or initialization can create them.

Known settlement ratchets its floor to the larger of prior floor plus the new
known upper-cost delta and the resulting cumulative public ledger. A matching
observed callback is credited once before SDK settlement; it does not remove a
pending ID. Duplicate callbacks, failed later projections and fresh-process
restore preserve that identity. Only the matching owned attempt can settle a
hold. The private observation bound prevents unbounded response history.

Interactive finite preflight owns the selected fresh or resumed run immediately.
Known probe usage is persisted before return to the UI. CLI and TUI reuse that
owner and do not replay `warm_up_usages`. An omitted limit restores the saved
limit; an ordinary option can tighten it, and cannot implicitly widen it. An
explicit interactive budget increase is a separate journal update. Legacy schema
1.0/1.1 receipts with neither private field nor activation file retain their
existing read/write behavior and version. Activation does not invent unknown
historical charges.

The worker's cold `ai-security-triage` command binds an explicit `ReportState` to
the existing run-directory helper's path for the input workspace and its scan ID,
the main scan's actual output layout. It hydrates that scan's known spend and saved total ceiling. The supplied
`--max-budget-usd` remains a separate triage phase allowance: quotes and new
triage costs consume it without counting prior main spend again or overwriting
the total ceiling. A legacy unactivated scan can establish a ceiling of its
known prior spend plus the explicitly supplied remaining allowance. Triage's
artifact contains only its own delta; the shared receipt contains both phases.
Disabled and cached triage returns perform no admission. A lost acknowledgement
retains its hold and blocks another cold paid invocation.

Finite `web_search` binds the same real scan owner. Missing global hooks can be
recovered with local `ReportUsageHooks` tied to that owner; no independent model
allowance is created. Its exact search ID is authorized once after client setup
and immediately before POST. Missing, stale, closed, deleted-stamp or consumed
financial authority makes zero POSTs and does not release uncertain allowances.
Uncapped search retains its existing behavior.

On POSIX, the implementation verifies directory handles, rejects symlinks and
unsafe ownership/permissions, uses exclusive private regular files, keeps the
owner lock stable, and requires file flush plus directory fsync around atomic
replacement. A failure poisons that process owner. This does not qualify power
loss guarantees for every remote or removable filesystem.

The Windows backend preserves native finite-run capability with qualified
Win32 handles: no reparse traversal, held directory handles, owner/ACL checks,
private creation, rejection of foreign directory mutation rights (including
`FILE_DELETE_CHILD`), `LockFileEx`, file flush and atomic `ReplaceFileW` document
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
current consumer `28bf8be4` parsers for schema 1.0, 1.1 and 1.2 (six offline
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
