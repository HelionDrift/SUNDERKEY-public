# Persistence port contracts

This increment defines a backend-neutral persistence boundary for SUNDERKEY. It
does not add a database client, execute SQL, migrate data, persist records,
authorize a deployment, or qualify a production environment.

## Backend direction

SQLite remains the local development and single-worker test backend. Its
declaration is intentionally limited to one concurrent worker. It does not
claim multi-writer coordination, high availability, online migrations, or
tenant isolation suitable for production.

PostgreSQL is the production port direction. Its contract requires multi-writer
coordination, high availability, tenant isolation, online expand-and-contract
migrations, optimistic concurrency, fencing, idempotency, and atomic outbox
enqueue. The declaration describes what an adapter must provide. It is not
evidence that such an adapter is deployed or verified.

## Immutable records

`BackendCapabilityDeclaration` records the exact behavior claimed by a pinned
adapter version. SQLite declarations fail closed if they claim production
deployment classes or production-only properties.

`MigrationManifest` binds an ordered sequence of content-addressed migration
artifacts to a backend and opaque store reference. Version steps must be
contiguous. PostgreSQL production manifests accept only the
`expand_contract` mode. No SQL or executable migration body is accepted.

`TransactionBatch` describes one all-or-nothing mutation intent. Every batch is
bound to one tenant, assessment, admitted scope, idempotency key, isolation
level, expected aggregate versions, fencing records, and content-addressed
operations. Outbox event references and an outbox enqueue operation must appear
together. The record is planning material only and has no persistence effect.

`DeploymentSuitabilityReport` compares deployment requirements with one
capability declaration. Every report retains the
`live_backend_verification_required` blocker. A compatible PostgreSQL contract
therefore reports `contract_compatible_unverified`, never deployable or
qualified. An incompatible capability reports the exact stable blocker codes.

## Production rejection rules

The suitability evaluator rejects SQLite for either production deployment
class. It also rejects worker counts above one, multi-writer requirements, high
availability, tenant-isolated production, and online migration requirements.
SQLite remains supported for local development and bounded single-worker
testing when the declared requirements fit its contract.

PostgreSQL compatibility does not remove the need for live adapter tests,
backup and restoration exercises, migration rehearsals, failover tests,
isolation verification, observability, credential custody, or operational
approval. Those checks require infrastructure and remain outside this module.

## Atomicity and outbox requirements

A conforming production adapter must commit the business operations, expected
version changes, fencing checks, idempotency reservation, and outbox enqueue in
one database transaction. External delivery remains outside that transaction
and must use the existing at-least-once outbox and idempotent receiver model.
The contract does not promise exactly-once behavior across an external side
effect and a database commit.

## Validation

The implementation provides canonical JSON, exact field checks, content
addresses, strict round trips, tamper rejection, and a Draft 2020-12 schema at
`registry/schemas/persistence-port-contract-v1.schema.json`.
