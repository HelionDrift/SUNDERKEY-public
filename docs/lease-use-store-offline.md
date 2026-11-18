# Local SQLite atomic lease-use store

`sunderkey.lease_use_store.SQLiteAtomicLeaseUseStore` implements the existing
`authorized_target_session_runtime.AtomicLeaseUseStore` two-method port. It
stores only the port's reservation request, reservation evidence and terminal
completion metadata. It has no provider, transport, clock, credentials, runtime
admission or signing implementation.

Creation is explicit: `SQLiteAtomicLeaseUseStore.create(path,
busy_timeout_ms=100)` exclusively creates one missing file under an existing
directory. `SQLiteAtomicLeaseUseStore(path, busy_timeout_ms=100)` only reopens
and verifies an owned file. Neither call adopts a foreign database, migrates,
repairs, creates parent directories or deletes an uncertain file. If creation
fails after exclusive file creation, `lease_use_store_initialization_failed`
means that the file is retained for caller inspection. Retrying creation does
not reinitialize it, even if the retained file is empty.

Creation captures the exclusive descriptor's regular, non-reparse file identity
before closing it. Initialization checks that identity before SQLite open and
again immediately after open, before any PRAGMA or schema access. The final
verify-only reopen remains bound to the same exclusive identity. A raced-in
empty file, foreign hardlink or coherent replacement is rejected; neither the
original uncertain file nor its replacement is deleted. Ordinary connections
also recheck their pinned file identity immediately after SQLite open. These
finite fences do not claim containment of arbitrary filesystem races.

## Reservation and settlement

`reserve(request)` captures and revalidates the exact native
`LeaseUseReservationRequest` before opening a connection. A `BEGIN IMMEDIATE`
transaction validates existing custody, inserts the reservation, validates the
resulting custody and commits before returning native
`LeaseUseReservationEvidence`. The existing request body, hash domain,
reservation key and evidence IDs are unchanged.

A `(lease_id, lease_sha256, lease_use_number)` is consumed permanently once its
reservation commits. Exact repeats and changed request/session contexts for
that consumed use are rejected. A `one_time` lease identity permits only one
reservation. The store additionally pins one consistent `lease_mode` for each
`(lease_id, lease_sha256)`; a different mode cannot evade that restriction.
Distinct valid use numbers remain possible for `session_bound` leases.

`complete(reservation, outcome, provider_called)` requires exact native evidence
that matches a committed reservation. It returns the existing native
`LeaseUseCompletionEvidence` after one verified transaction. A duplicate or
conflicting completion is rejected, not returned as cached success. The native
zero-call form is `outcome='rejected_before_authentication'` and
`provider_called=False`. Completion does not remove, refund or reopen a use.

Provider failure, failed completion, or a lost acknowledgement does not trigger
an automatic retry or fallback. A committed reservation remains consumed even
when the caller has no acknowledgement or completion evidence. A failed or
uncertain operation is not proof that a reservation or completion rolled back.
This store never infers provider execution from its metadata.

## Local integrity and durability policy

The file has a fixed application ID, schema version 1, store-kind marker, schema
digest and exact closed SQL manifest. Every positive operation verifies the
entire bounded reservation/completion custody, canonical stored JSON, native
field types, original content addresses, SQL projections and reciprocal
reservation/completion references. Ordinary SQL updates, deletes and
`INSERT OR REPLACE` attempts are blocked by immutable/no-replacement triggers,
including when `recursive_triggers` is off. Missing or changed guards are
rejected by manifest verification. These guards are defense in depth, not
authentication of arbitrary database writers.

Only DELETE journal mode is supported. Each owned connection uses and checks
`foreign_keys=ON` and `synchronous=FULL`; read connections also use
`query_only=ON`. Application/schema/store ownership and journal policy are
verified before connection configuration. A foreign database receives no
configuration PRAGMA writes. An existing WAL database is rejected without
conversion. A caller-altered unsafe owned connection is rejected at use, not
silently repaired. Synchronous and foreign-key settings are connection-local;
this is not proof of another connection's previous settings.

Every writer open has a preceding read-only ownership/schema/journal preflight.
Initialization also checks the exclusively created empty file read-only before
its first writer open. The actual writer still verifies file identity, ownership
and the transaction snapshot; preflight is not a substitute for those fences.
Opening a foreign file read-write can let SQLite recover a hot rollback journal
before a schema check rejects it. This leaf instead refuses when read-only
verification cannot complete, preserving the database and journal without
automatic recovery. This applies to an owned hot journal as well as foreign or
corrupt bytes substituted in-place while retaining the selected file identity.
Recovery is an external caller decision; there is no recovery or repair API.
These separate observations do not contain arbitrary changes between preflight
and writer open or authenticate the filesystem.

`busy_timeout_ms` must be a native integer from 0 through 1000. Bounded SQLite
contention returns `lease_use_store_busy`, distinct from corruption or database
failure, without an application retry. The fixed 4096-record ceiling per table
and 4096-byte canonical document ceiling are local software-cost bounds, not
lease authority. Oversized stored documents and identity fields are SQL-bounded
before retrieval. There is no eviction or compaction that releases consumed
uses.

Paths must be exact native strings or the platform's concrete `Path` type,
absolute and unambiguous, with existing ordinary parent directories. Caller
URI, UNC, device, alternate-stream, dot-segment and ambiguous trailing-name
forms are rejected. Observed symlink/reparse paths are rejected; an opened
store also pins the observed file identity. These checks do not authenticate
the backing filesystem, contain a hostile filesystem race, detect restoration
of an older coherent file, establish distributed/HA durability or prove a
physical power-loss recovery guarantee.

## Authority and evidence limits

The existing reservation request contains no tenant, `max_uses`, signed lease
body or authoritative validity times. The store therefore cannot establish
those facts, inspect current scope or revocation, or authorize a session. The
runtime still owns signed-scope admission, lease/request binding, currentness,
safety/revocation refresh, provider invocation, settlement and cleanup. The
request's native use-number format remains 1 through 100; that format is not a
new maximum-use grant. Hashes and canonical metadata consistency do not create
independent authenticity.

The focused tests use disposable local databases, genuine existing synthetic
signed-scope fixtures and inert providers. They compare native evidence with
the existing in-memory reference, exercise restart and competing independent
workers, verify committed custody before a provider callback, and show zero
duplicate provider calls after adverse or uncertain outcomes. These observations
are `reference_simulation_nonqualifying`. They do not establish live provider
acceptance, target authority, deployment readiness, parity or qualification.
