# Local SCIM idempotency store

`sunderkey.scim_idempotency_store.SQLiteScimIdempotencyStore` implements the
existing `AtomicScimIdempotencyStore` protocol with an explicitly selected
local SQLite file. This is durable local coordination for the existing test
and staging dispatch boundary, not an identity provider or production service.

## Explicit construction

```python
from pathlib import Path
from sunderkey.scim_idempotency_store import SQLiteScimIdempotencyStore

store = SQLiteScimIdempotencyStore(
    Path("C:/operator-selected/scim.sqlite3"),
    store_id="store:operator-selected-scim",
    busy_timeout_ms=5000,
)
```

The caller supplies both the absolute local file path and stable store ID.
The parent directory must already exist. There is no default location,
directory creation, URI, UNC, device path, in-memory backend, credential,
network client or provider discovery. Windows alternate streams, reserved
device names and trailing-dot or trailing-space aliases are rejected.

A missing leaf is created exclusively with `O_CREAT | O_EXCL`, then opened as
an existing file. A file appearing after the absence sample is rejected,
not adopted. The captured regular-file identity is checked around SQLite
open. Only the exclusively created leaf can receive versioned schema metadata,
the exact store ID and `local_nonproduction_coordination` scope. An existing
zero-byte or unmarked empty database is not a new store.

Existing identity and schema are checked using a read-only connection before
writer configuration. Existing foreign databases, MissionStore files, wrong
application or schema markers, changed identity,
unknown schema objects and altered immutable guards fail without logical
writes. No database is silently adopted, reset or migrated. Initialization
failure preserves the uncertain file, including an unmarked partial file;
the next construction cannot silently reinitialize or delete it.

## Reservation before dispatch

`reserve` has the existing keyword-only protocol signature. It accepts native,
bounded identifiers, SHA-256 addresses, canonical UTC timestamps and only the
native environment strings `test` or `staging`. The SQLite write transaction
commits an append-only reservation before returning the existing
`ScimIdempotencyReservation` record. Independent connections therefore observe
the held key before the injected dispatcher can be called.

The token is a deterministic content binding of the selected store and exact
reservation inputs, not a secret, signature or authority capability. The
existing reservation domain, body and address rules are unchanged.

A key already reserved or completed returns `None`, including an attempt to
bind it to another command, admission, dispatcher, environment or timestamp.
The existing dispatch function treats that result as denial before dispatch.
Bounded SQLite busy or locked reservation attempts also return `None` without
retry. Other storage or content-integrity failures raise
`ScimIdempotencyStoreError`; the existing dispatch function rejects them.

## Completion and uncertain outcomes

`complete` accepts the native existing reservation record, captures and
reconstructs its declared fields, verifies its original content address, and
requires the exact held database record. It binds the exact result digest and
caller-supplied completion time. Completion cannot precede reservation.
Successful completion adds one immutable existing
`ScimIdempotencyCompletion` record in a separate atomic SQLite transaction.
Any second completion is rejected, even with identical values.

The records are stored as bounded canonical ASCII JSON with their existing
IDs and hashes. Reads verify closed native field shapes, duplicate keys,
canonical bytes, content addresses, indexed bindings and known chronology.
Schema object kinds, names and SQL are byte-bounded in SQLite before they are
retrieved into Python, then compared against the exact closed manifest.
Ordinary SQL update, deletion and replacement of metadata, reservations or
completions are blocked. Insert guards check every primary and unique binding
before a replacement could delete old custody, including `INSERT OR REPLACE`
when SQLite recursive triggers are off. There is no expiry, release, deletion,
repair, automatic rehash or automatic retry operation.

A dispatch exception, invalid result or failed postcondition leaves the
already committed reservation held. A completion failure cannot release it.
If completion committed but its acknowledgement was lost, the reservation
and terminal completion remain present and later dispatch is still denied.
No failed call claims to undo an external effect or to determine an uncertain
provider outcome. A failed reservation transaction before commit returns no
positive reservation and cannot lead to dispatch.

If reservation committed but its acknowledgement was lost, the key remains
held even though the dispatcher was never called. No expiry or automatic
retry interprets that uncertainty as permission to dispatch.

## Authority and durability limits

The original policy, actor, command, admission, authenticated verifier,
dispatcher attestation and evaluation-time checks remain in
`dispatch_validated_provisioning`; this leaf does not change those parsers or
current-use gates. Direct store calls do not authenticate those declarations.
No signer, authenticated identity, fresh clock or production authority is
fabricated. All receipt effects and qualification boundaries are unchanged.

SQLite uses local atomic transactions, the default DELETE journal mode,
foreign-key enforcement and full synchronous commits. A changed journal mode
is rejected, not silently reset or adopted. Actual filesystem custody,
permissions, encryption, hardware persistence, backups,
rollback resistance, high availability and disaster recovery remain external
controls. The store ID is a caller-selected label, not proof of global
uniqueness or authenticated deployment identity. Separate files do not share
a replay fence even if their labels match. Valid records are not signatures,
identity-provider acknowledgements or qualification evidence.

The implementation is not a sandbox for arbitrary Python callbacks, a defense
against concurrent filesystem replacement, or proof that an independently
restored or deleted database retains its original history. An existing store
object will not silently recreate a missing file. Operators must preserve the
selected database and investigate uncertain effects; the module provides no
automatic recovery or replay authorization.

## Regression evidence

`tests/agents/test_scim_idempotency_store.py` reuses native Phase176 policy,
command, admission and result fixtures with an inert admission verifier and
dispatcher. It does not invoke the fixture's unrelated OIDC key generator.
The tests exercise commit-before-callback visibility, reopen, independent
workers, competing reserve and dispatch, every reservation binding field,
terminal result binding, adverse dispatch, transaction rollback, lost
acknowledgement, busy and corrupt storage, exact stored replay, immutable
guards and rejection of foreign databases including a disposable MissionStore.
They also cover preserved empty and raced-in files, read-only preflight,
uncertain initialization and direct replacement denial without dropped guards.
These are local software checks only, with no provider or target calls.
