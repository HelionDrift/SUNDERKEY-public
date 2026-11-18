# Local API Runtime Adapter

This increment supplies a concrete local runtime beneath `LocalApiService`. It
combines a crash-safe, file-based SQLite `ServiceRepository` with a
framework-neutral ASGI 3 callable. The callable is invoked in process and does
not bind a port or open a socket.

## Implemented Behavior

`SQLiteServiceRepository` applies a content-addressed migration and configures
SQLite with write-ahead logging, full synchronous commits, foreign-key checks,
and a bounded writer lock. One immediate transaction atomically writes the
resource, append-only audit entry, integration event, and idempotency result.
Any failed write rolls back all four records.

Repository lookups and ordered pages always bind resource kind, tenant, and
context. Resource identifiers are ordered lexically for stable cursor paging.
Updates compare the exact concurrency token and the exact prior record inside
the writer transaction. Idempotency replays are tenant and context scoped and
reject an attempt to bind the same idempotency digest to another request.

Persisted resources, audit entries, events, and replay results have independent
content digests. Point reads and atomic commits check the stored digest and
SQL row identity before using a resource or replay result. `verify_integrity()`
reads a consistent SQLite snapshot, runs the SQLite quick check, verifies each
digest and row identity, and reconciles every resource version with exactly one
retained audit entry, integration event, and idempotency result. It verifies
historical audit links and the current resource head. Reopening the repository
checks the embedded migration identity before use.

Retained idempotency results must reproduce their complete JSON document and
self-contained resource, audit and event joins after the raw hash check.
Duplicate or discarded fields and equal-valued native type substitutions are
rejected. Actual update commands also preserve the prior creation time. These
[integrity checks](offline-contract-api-integrity.md) do not authenticate
repository metadata independently or invent absent prior snapshots on replay.
The store-wide check proves local consistency, not tamper authenticity against
an actor who can rewrite the SQLite file and all related records coherently.

## ASGI Boundary

`LocalApiAsgiApp` accepts one route:

```text
POST /v1/service/requests
Content-Type: application/json
```

The JSON request maps directly to the version 1 service request contract. The
adapter calls the injected `AccessAuthorizer` for every request and the injected
`MutationAdmitter` for every mutation. It never derives authority from caller
claims alone.

The boundary limits a body to 131072 bytes, headers to 64 fields and 16384
bytes, and pages to 100 resources. It rejects duplicate headers, query strings,
unsupported media types, credential-bearing headers, credential value fields,
and filesystem paths in wire data. Credential references remain permitted.
Successful and failed responses carry a stable correlation ID and disable
caching. Errors use bounded public messages and never echo request values or
internal exception text.

The version 1 request vocabulary includes `attach_target_context` for callers
that already hold a complete target-context bundle. The adapter accepts only
the bundle document, never a caller filesystem path. Byte intake is handled by
the bounded in-process attachment facade before this transport boundary, so
raw source content is not stored by the local service.

The schema at
`registry/schemas/local-api-runtime-adapter-v1.schema.json` validates requests,
success envelopes, and error envelopes.

## Deliberate Boundaries

This adapter is for local development and evaluation. It does not provide:

- a network listener, ingress controller, or API gateway;
- TLS termination or certificate lifecycle management;
- live authentication, session establishment, or credential validation;
- high availability, replication, backup, or disaster recovery;
- PostgreSQL or another production database adapter;
- integration-event delivery workers;
- live target access or offensive actions;
- production deployment or security qualification.

A production host must derive the access context from authenticated identity,
protect the ASGI boundary with TLS and ingress controls, inject production
authorization and admission policy, provide a qualified durable repository,
and independently operate event delivery. Those external controls cannot be
proven by this repository-only increment.

## Verification scope

The focused tests invoke ASGI entirely in process. They cover restart replay,
migration identity, atomic rollback, optimistic concurrency, append-only audit
history, integration events, stable pagination, tenant and context isolation,
wire limits, credential and path rejection, normalized errors, schema
validation, and repository reopening. No test opens a socket or contacts a
target.
