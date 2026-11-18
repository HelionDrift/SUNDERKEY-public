# PostgreSQL runtime adapter

## Purpose

`sunderkey.postgresql_runtime_adapter` is the concrete PostgreSQL SQL boundary for
the existing persistence port, durable scheduler, and durable artifact recorder
contracts. The adapter accepts a caller-supplied DB-API connection factory. The
module does not discover credentials, read a DSN, import a database driver, open a
socket during import, or create a database.

The implementation is repository complete but operationally unqualified. A real
PostgreSQL deployment, its identity controls, backups, failover, row policies,
monitoring, and live conformance evidence remain infrastructure work.

## Implemented behavior

The adapter provides:

- serializable transaction execution through an injected connection factory;
- tenant-bound aggregate reads and writes;
- assessment and scope binding on idempotent transaction replay;
- optimistic aggregate version checks;
- resource fence token and fence epoch checks;
- atomic aggregate, outbox, transaction, and receipt persistence;
- exact migration identity verification before every operation;
- deterministic classification of retriable and terminal SQLSTATE failures;
- transaction rollback on contract errors and driver failures;
- content-addressed transaction receipts;
- content-addressed health and capability observations;
- durable artifact commit observations compatible with the artifact recorder;
- tenant-bound schedule registration and occurrence materialization;
- scheduler claims using `FOR UPDATE SKIP LOCKED`;
- scheduler claim idempotency and worker context binding.

The adapter implements the existing `PersistenceRepository`, `PostgreSQLAdapter`,
and artifact persistence boundaries by structure. Package-level exports are left
to the integration increment so this repository-only work stays isolated.

## Required database contract

The connection factory must return a DB-API style connection with `cursor`,
`commit`, `rollback`, and `close`. Its cursor must support `execute`, `fetchone`,
`fetchall`, `rowcount`, and `close`.

The target database must already contain the schema represented by
`POSTGRESQL_MIGRATION_PLAN` in `persistence_scheduler_runtime`. The adapter does
not run administrative DDL. It verifies version 1 against both:

- `migrationref:persistence-scheduler-runtime.postgresql.0001-expand`
- the embedded SHA-256 migration content address

An absent or changed identity raises `MigrationIdentityError` and rolls back.
This prevents code from operating against an unknown schema.

The migration must supply tenant-keyed versions of these logical tables:

- `schema_migrations`
- `aggregate_heads`
- `resource_fences`
- `transaction_batches`
- `outbox_events`
- `runtime_receipts`
- `schedules`
- `occurrences`
- `lease_snapshots`
- `scheduler_results`

Production DDL, row-level security policies, grants, indexes, and partitioning are
deployment artifacts. They are intentionally not inferred or applied by this
adapter.

## Isolation and replay rules

Every read and mutation includes a tenant predicate. The adapter does not query
other tenants to distinguish an absent object from a cross-tenant object. This
avoids disclosing cross-tenant existence through error behavior.

Transaction idempotency is keyed by tenant and idempotency key. A replay is
accepted only when assessment, scope, batch identifier, and batch digest all
match. Scheduler claim replay also requires the same schedule and worker. Any
rebinding raises `IdempotencyConflict`.

Each aggregate head is locked, checked against the expected version, and advanced
once. Each resource fence is locked and matched by both token and epoch. Lost
update races raise `ConcurrencyConflict`. Outbox rows and the content-addressed
receipt are inserted in the same transaction as aggregate state.

## Failure policy

The classifier treats these SQLSTATE categories as retriable:

- `40001`: serialization failure;
- `40P01`: deadlock detected;
- `55P03`: lock not available;
- class `08`: connection interruption.

Integrity, privilege, missing relation, and unknown failures are terminal. Unknown
failures default to terminal so an unrecognized error cannot authorize an
automatic retry. Exception messages and SQL parameters are not copied into
receipts.

The adapter performs one transaction attempt. Retry count, delay, and budget are
caller decisions governed by the existing scheduler contracts.

## Health and capability observation

`observe_health` validates the exact migration identity and a one-row database
probe. It then binds the result to the existing PostgreSQL production capability
declaration. The observation records that the injected connection factory was
invoked and explicitly sets:

- `live_deployment_proof` to `false`;
- `qualification_effect` to `none`;
- `deployment_qualification` to `none`.

This record proves only what the adapter observed through that injected
connection. It does not prove high availability, backup recovery, latency,
regional residency, row-level security, or production readiness.

## Receipt validation

Transaction and health records are covered by
`registry/schemas/postgresql-runtime-adapter-receipt-v1.schema.json`. Each record
contains a deterministic identifier and SHA-256 content address. Parsers rebuild
the record and compare canonical output, so changed content with an old address
fails closed.

## Verification boundary

The focused tests use deterministic in-memory fake DB-API connections. They cover
commit and rollback, migration mismatch, stale versions, stale fences, tenant
isolation, replay context binding, atomic outbox behavior, failure classification,
scheduler claims, artifact observations, schema validation, and content-address
tamper rejection.

The fake connection is not a PostgreSQL substitute and is not live deployment
evidence. Infrastructure qualification still requires the opt-in conformance
harness checks declared by `postgresql_conformance_metadata`, including actual
serialization conflicts, skip-locked behavior, row policies, connection loss,
atomic rollback, and expand-contract migration behavior.
