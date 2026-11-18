# Persistence and scheduler runtime

This increment provides a concrete file-based SQLite runtime for local development and
single-worker testing. It turns the existing persistence port and durable scheduler
contracts into transactional repository behavior without claiming production readiness.

## Implemented behavior

The SQLite adapter provides:

- an embedded, content-addressed schema migration with identity verification on every
  reopen;
- tenant-scoped aggregate heads with optimistic versions;
- exact fencing-token and fencing-epoch checks;
- atomic aggregate updates, idempotency recording, and outbox enqueue;
- content-bound transaction replay and rejection of idempotency-key rebinding;
- durable schedules, occurrence materialization, transactional due claims, lease
  heartbeats, completion, bounded retry, dead-letter disposition, cancellation, and
  expired-lease recovery;
- a unique active-lease constraint per tenant and occurrence;
- injectable UTC clocks and bounded SQLite writer-lock waits; and
- full durability across process restart through a caller-selected database file.

SQLite uses `BEGIN IMMEDIATE`, WAL journaling, full synchronous writes, unique constraints,
and explicit version predicates. Multiple processes may open the database, but this adapter
remains intentionally classified as local development only. SQLite is not the production
multi-worker or high-availability backend.

## PostgreSQL boundary

`PostgreSQLAdapter` defines the production repository surface and
`POSTGRESQL_MIGRATION_PLAN` records the required expand-contract plan. The plan requires
tenant-scoped keys, row locking, `SKIP LOCKED` due selection, atomic outbox writes, fencing,
and idempotency constraints.

`postgresql_conformance_metadata()` describes an environment-gated harness using
`SUNDERKEY_POSTGRES_CONFORMANCE_DSN`. Reading that metadata does not open a connection. No
live PostgreSQL test, network effect, production deployment, or production qualification is
claimed by this increment.

## Transaction boundaries

Every mutation executes in one database transaction. A failed fence, stale aggregate
version, duplicate outbox event, stale lease, or conflicting idempotency key rolls back the
entire mutation. Scheduler state changes and their outbox entries commit together.

The runtime never derives authority. Callers must provide schedules and transaction batches
that have already passed SUNDERKEY authorization and policy controls.

## Remaining infrastructure work

Production use requires a concrete PostgreSQL driver adapter, a provisioned PostgreSQL
service, tenant row-policy verification, connection-loss injection, concurrent multi-worker
stress, backup and restore exercises, operational telemetry, and deployment qualification.
Those checks cannot be honestly completed from repository-only execution.
