# Local sequential execution-state repository

`src/sunderkey/sqlite_execution_state_repository.py` implements the unchanged
`ExecutionStateRepository` port with a caller-selected local SQLite file. It is
an offline software implementation, not deployed capacity, action authority,
provider acceptance or independently qualified execution.

## Supported construction and use

Create `SQLiteExecutionStateRepository` with an explicit absolute local
`database_path`, `namespace`, `tenant_id`, `expected_binding`, `expected_policy`
and `initial_state`. No parent directory is created. These are caller
declarations, not verified tenant ownership, a current lease or a trusted clock.
An existing file must already be this exact repository with the same original
configuration. Opening never reseeds the current state from a newer snapshot.

V1 requires the policy's native `sequential_only` flag to be `True`, one exact
fixed binding and policy, and an initially idle state with no active sessions,
active execution or outstanding reservation. Both existing fixed-window and
integer-token-bucket algorithms are supported. The original policy, lease,
fence, health, stop flags and initial counters remain fixed. There is no policy
rotation, health update, lease renewal, reset, refund, recovery, migration or
concurrent completion merge.

Use `execute_with_durable_controls(request, policy, clock, repository,
transport)` as the supported execution helper. It validates and reconstructs
the complete native request and policy, including their original addresses,
before invoking the unchanged `execute_with_controls` runtime. Its owned
clock observations and transport delivery copies reject native aliases and
late callback mutation. A rejected transport callback is represented using the
existing transport-exception path; rejection cannot undo a transport effect
that may already have occurred.

The original port's `lookup(binding, idempotency_key)` does not receive an
actual request or policy. Calling `execute_with_controls` directly can still
return an old receipt for a malformed actual request carrying an old digest
before the repository has a chance to inspect that request. The new helper
addresses this input-correlation gap without changing the public port. It does
not isolate the process from arbitrary malicious Python code or protect an
object after another process has replaced all of its captured values.

## Reservation, settlement and history

A successful reservation atomically appends the full request, admission clock,
before state and expected reservation state, then advances the singleton head
by an exact state/version compare-and-swap. The commit occurs before transport.
Budgets are spent even when transport fails. They can roll over or refill only
through the unchanged declared rate algorithm, not through reopening a file.

Completion requires the exact outstanding reservation, request and completion
clock. It reconstructs all admission and execution joins, original receipt
identities, retry disposition, cleanup declaration and expected completion
state. Immutable outcome insertion and the exact head update commit together.
Native booleans, counters, enums, timestamps and full canonical projections are
checked rather than relying on Python equality or a supplied digest alone.

The unchanged state contains only one reservation request digest and derives
completion from that reservation. V1 therefore refuses overlapping work. It
does not synthesize a merge for concurrent reservations.

An unverified local settlement leaves the last reservation held. Reopening,
trying another key, waiting for a rate period or supplying a different initial
state cannot release it. A lost reservation acknowledgement produces no
transport call through the helper even if that reservation committed. A lost
completion acknowledgement may mean the complete terminal record already
committed: the caller can inspect that record, and exact replay returns it
without another transport call. This is not an external rollback guarantee.

Declared transport failures, including transport exceptions, are terminal
local outcomes under the unchanged protocol and are retained with spent
budgets and the original pending-cleanup evidence. They do not prove the
transport made no external change or completed cleanup. No automatic retry is
performed. A later explicit attempt retains the existing rule that a
`prior_execution_sha256` is a digest-shaped reference; this leaf does not add
an unapproved requirement to resolve it to an earlier local outcome.

`lookup` and `current_state()` reconstruct bounded immutable local history and
return detached native models. Old receipt identity and timestamp spelling,
including microseconds, are preserved. Historical lookup does not consult a
current clock or make an expired lease current. It grants no permission to use
the result, run a new action, access a target or bypass current authority.

## Local storage subset and failure handling

The leaf uses a distinct application/schema identity and exact expected SQL
objects. Existing empty, foreign, MissionStore, differently configured or
unknown-schema databases are refused. Existing-file ownership is inspected
through a read-only connection before any read-write open, because SQLite can
recover a hot journal as part of opening a writer. An unreadable hot journal
fails closed. Owned writer checks repeat inside the transaction.

Missing files use exclusive OS creation and retain the created descriptor's
device/inode identity through an initial read-only empty-file preflight, the
writer open and final read-only reopen. An observed empty-file substitution
after exclusive creation is refused rather than initialized. A same-inode
foreign hot journal is inspected read-only before any writer can recover it.
If an empty file, hardlink or final symlink appears before exclusive creation,
it is not adopted. Partial or uncertain initialization files are preserved,
not deleted or automatically initialized on another open. Only regular local
files, existing parent directories and final symlink/reparse rejection are
supported. URI, UNC, device, stream, relative and ambiguous spellings are
rejected. This is not a defense against parent-directory symlinks or arbitrary
concurrent filesystem replacement, and it is not cold rollback detection.

Every owned connection requires `DELETE` journal mode, `FULL` synchronous
writes, foreign keys enabled and zero busy timeout. External WAL mode is
rejected without switching it. There is no lock retry. SQL guards deny row
updates/deletes and `INSERT OR REPLACE` on metadata, reservations and outcomes;
the head accepts only a one-version step. Head updates still require exact
matching immutable history, not just the SQL step guard.

Finite V1 storage limits are 1,024 reservations, 16 MiB of aggregate stored
history text, 64 KiB per canonical document, 512 printable ASCII characters
per model string, nonnegative signed-64-bit integers, 64 allowed windows and
256 retry codes. Stored JSON is limited to 4,096 nodes and depth 12. Paths are
limited to 4,096 printable ASCII characters. These are this local leaf's
supported subset, not changed bounds on the original contracts. Arithmetic
and timestamp overflow fail closed. Count and aggregate byte checks run in SQL
before materializing history; individual SQL projections are bounded before
decoding. Duplicate keys, floats, nonfinite values, subclasses, original
address omissions and noncanonical JSON are refused.

Local record hashes bind the captured configuration, but are not signatures.
Namespaces and tenant coordinates partition explicit local files only; they
do not provide global replay protection, tenant read authority, current trust,
anti-rollback, a production durability qualification or operator permissions.

## Verification

`tests/agents/test_sqlite_execution_state_repository.py` uses the genuine native
Phase 171 builders, inert clock/transport adapters and disposable files. It
checks both rate algorithms, old receipt goldens, reopening, spent budgets,
worker competition, pending holds, lost acknowledgements, exact reciprocal
records, native and SQL negatives, real foreign hot journals and creation
races. The real Windows final-symlink test is skipped only when the account
lacks OS symlink creation privilege; a separate mocked flag test proves the
denial code path, not OS containment. No live infrastructure, credentials,
provider calls, target operations, production keys or acceptance are used.
