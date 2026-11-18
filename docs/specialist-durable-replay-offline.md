# Local durable specialist replay reservations

`specialist_durable_replay` supplies an explicit file-based SQLite reservation
adapter for the existing web/API and cloud/identity specialist boundaries. It
closes the process-restart gap in their process-local replay guards. It does not
add a specialist tool, network transport, credentials, signing, action authority,
qualified clock, production deployment or live acceptance evidence.

## Explicit bindings and supported calls

Create `SQLiteSpecialistReplayStore` with an absolute local database path, a
caller-selected `replayns:` namespace and exact `tenantref:`. Its parent must
already exist. There is no default path, namespace, tenant or runtime adapter.
The module accepts bounded native ASCII path spellings up to 4,096 characters.
It rejects relative, in-memory, URI and UNC paths, dot components, repeated or
trailing separators, incompatible databases, nonregular database paths and
final-path symlinks. On Windows it also rejects drive-relative and device paths,
alternate data streams, reserved device names and trailing-dot/space components.
A native `Path` has already normalized its spelling; this adapter validates
that resulting representation rather than recovering discarded caller text.
It never creates missing parent directories. This is a local filesystem
boundary, not proof that a drive is physically local or independently protected.
Do not point it at a MissionStore or another application's database.

A missing file is created with exclusive `O_CREAT | O_EXCL`, no-follow where
the platform supports it, and immediate regular-file checks. The handle is
closed before SQLite opens only that existing path in `rw` mode. A file or
link that appears before exclusive creation is refused rather than adopted.
An uncertain empty or partial file is preserved and is not reinitialized later.
These checks address the demonstrated pre-open adoption race. They do not
protect against arbitrary concurrent filesystem replacement, parent-directory
substitution or a valid cold rollback.

`SQLiteWebApiReplayGuard(store, expected_context=...)` preserves the existing
`reserve(request)` and `contains(idempotency_key)` methods. It reconstructs the
complete exact native request and compares its context before reservation.
Pass it to the unchanged web/API `execute_specialist_action` function. Facades
retain their original store selection and reject late store redirection.

`SQLiteCloudIdentityReplayGuard(store, expected_request=..., expected_context=...)`
captures an exact native cloud request and preserves `reserve(idempotency_key)`.
Its `expected_request` property returns a detached reconstructed copy.

Use `execute_cloud_identity_with_durable_replay` for cloud dispatch. This helper
compares the complete actual request and supplied context to the captured inputs
before delegating to the unchanged cloud execution function. It dispatches an
owned copy and rejects a changed delivered request before returning a positive
receipt. Calling the original cloud function directly with the string-only
facade cannot independently correlate its actual first-call request to the
captured request: that port receives only a key string. The helper supplies this
missing correlation without changing the existing public port.

## Native source and storage integrity

Only the exact existing request, context, approval, session, budget and enum
families are accepted. Tuple fields must be native tuples, text native bounded
ASCII, booleans native booleans and counters native signed-64-bit integers.
Bool/integer, integer/float and scalar/container subclass aliases reject before
normalization. The existing constructors reproduce original request addresses,
semantic bindings and canonical ordering; cleared or substituted addresses and
late changes to borrowed source values cannot redefine a stored reservation.

This local V1 adapter supports at most 256 web sessions, existing evidence and
scope-array limits, 512 characters per scalar field, 262,144 bytes per stored
request projection, 4,096 parsed JSON nodes and depth 12. These are finite adapter
limits, not changes to the unchanged specialist contracts. Projection parsing
rejects duplicate members, floats, nonfinite numbers and noncanonical JSON.

Each reservation stores the exact family, namespace, tenant, key, request ID,
request digest, context digest and native model projection under a content hash.
Lookup reconstructs the matching row and checks all projections. Schema,
application identity, format metadata and append-only triggers are checked on
each transaction. Selected SQL text is byte-bounded before Python retrieval and
JSON decoding. SQL tables use strict types and one unique reservation key.
Unknown databases, existing unmarked empty files, wrong application/schema
markers, extra schema objects and MissionStore files are refused without logical
writes, never adopted, migrated or overwritten.

## Atomic reservation and failure semantics

The unique key is `(namespace, tenant_ref, idempotency_key)` within one selected
database. It spans both specialist families and all workers using that database,
namespace and tenant. It is not global replay coordination across separate files.
Another worker, request, context or family cannot rebind an existing key.
Explicitly selecting a different namespace or tenant is a separate partition,
not a mechanism that grants renewed authority or an automatic retry.

Reservation uses one `BEGIN IMMEDIATE` transaction and full synchronous writes.
This V1 leaf supports only SQLite `DELETE` journal mode. Every owned connection
checks that mode, full synchronous operation and zero busy timeout. Construction
and every reservation first check an existing database's ownership, exact schema
and journal mode through a read-only connection before any writable SQLite open.
The writer then rechecks its own transaction snapshot before insertion. A hot
journal that requires recovery fails closed without modifying the selected
database or journal; this leaf does not automatically recover uncertain files.
A newly created file must first reproduce an unmarked empty database;
foreign stores are not configured. A persistently selected external `WAL` mode
is rejected, not automatically switched. This is a conservative supported local subset,
not evidence that WAL inherently causes duplicate execution or is unsafe.
It commits before the existing execution boundary can call its adapter. Busy,
corrupt, missing or uncertain storage fails closed with no automatic retry.
Independent connections and reopened facades see the held reservation.

Every reservation remains held permanently. Successful observations, adapter
exceptions, invalid observations and uncertain external results do not release
it. There is no delete, reset, expiry, completion or retry API. A lost local commit
acknowledgement may leave the reservation held even though no adapter was called;
the next attempt still rejects. A rejection after an adapter call cannot undo
an already external effect or prove cleanup. Source/request checks are not an
arbitrary same-process Python sandbox.

## Verification and remaining boundaries

Focused tests use the native Phase166 and Phase167 request builders and inert
adapters, disposable SQLite files and synthetic timestamps. They cover valid
dispatch, detached input ownership, reopen, competing workers, tenant/context
denial, cross-family rebinding, busy storage, adverse results, lost commit
acknowledgement, restored-schema record corruption, path rejection before SQLite,
preserved foreign databases and hot journals, persistent-WAL denial,
exclusive-creation races and zero second invocation. A genuine crashed-process
fixture shows the earlier writable identity query recovering a foreign hot
journal, while current construction and reservation reject without changing
either file. The real final-symlink race test runs only where the
platform permits creating its disposable fixture. Windows without that privilege
reports an explicit skip. Genuine empty-file and hardlink race tests still run;
the separate mocked late-link flag test proves its code-path denial only, not
operating-system containment.
No test contacts a cloud account, target, identity provider or credential store.

This is a local replay adapter, not a distributed authority ledger, HA database,
signed anti-rollback anchor, authenticated evidence repository or durable
production acceptance result. Protection relies on retaining the caller-selected
database and namespace. Deleting it, choosing a fresh database or restoring a
valid older snapshot is not detectable through a trusted cold rollback anchor
in this module. Filesystem ACLs, backup/restore custody, independent integrity
monitoring and production qualification remain external.

The helper delegates the existing request, approval/session windows, context,
scope, budget and observation checks. Deployment must still route action use
through its current authority, environment, health, stop and evidence controls.
This leaf does not add those runtime gates, authenticate caller-supplied
specialist declarations or spend authority from MissionStore. Durable SCIM and
target-session lease-use custody are separate ports, not implemented by this module.
