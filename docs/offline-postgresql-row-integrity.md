# Offline PostgreSQL row integrity

The injected PostgreSQL persistence/scheduler adapter now checks selected native
row projections against their exact canonical documents before returning or
using them. This is an integrity repair for existing operations, not a new
database deployment, authority operation, migration or scheduler lifecycle.

## Existing operation joins

Transaction replay requires the stored tenant, idempotency key, assessment,
scope, batch ID and digest to match the supplied batch. The complete stored batch
JSON must replay through the existing contract and reproduce the supplied
canonical document. A matching digest projection alone is insufficient.

Schedule registration replay and schedule loads bind the stored tenant,
schedule ID, digest and definition version to the canonical schedule document.
The cancellation column must be a native boolean. Fresh materialization and
claims retain the existing cancellation denial. A selected claim candidate must
bind its tenant, schedule, occurrence ID and index to the original occurrence
document and selected schedule. Mutable occurrence version, attempt and fence
columns are validated as native integers before arithmetic. The origin document
is not rewritten to invent a new historical occurrence address.

Cached claims require the exact original tenant, key, schedule and worker, the
stored result SHA, and an original claim transition. The result must reproduce
the persisted version-one lease snapshot, including all canonical content and
its tenant, lease ID/version, occurrence, fence and expiry projections. A valid
heartbeat is not a claim result. An independently readdressed claim cannot
substitute a different schedule digest or occurrence version while retaining
the original snapshot.

Historical exact claim retry does not re-evaluate the original claim at today's
clock, re-activate a cancelled schedule, renew a lease or grant target authority.
The original snapshot may be inactive and expired; exact stored history still
returns unchanged. This adapter remains limited to schedule registration,
materialization and claims, not heartbeat or terminal settlement operations.

## Native documents and bounded failure handling

Receipt parsing and row-document replay reject numeric schema aliases,
booleans in integer fields, floats, duplicate fields, dropped or contradictory
content, non-native scalar aliases and malformed wrappers. Both mapping and
tuple DB-API row shapes remain supported. Public typed batches and schedules
are replayed into detached owned inputs before the injected connection is used.

Each supplied/stored document has a local 1 MiB canonical JSON byte budget,
depth 24 and 50,000-node ceiling. Repeated shared subtrees and escaped strings
are charged before canonical serialization. These are software-cost bounds,
not schedule, tenant, retention or lease authority. Database integer projections
retain the signed 64-bit storage bound; the pure contract representation is not
changed. Stored JSON must match the canonical text written by this adapter.

The adapter performs one transaction attempt and attempts rollback and both
cleanup operations without leaking raw driver cleanup failures. If commit was
attempted and acknowledgement or cleanup fails, the error explicitly reports an
uncertain outcome. A rollback failure is also uncertain. Neither a cleanup error
nor a lost acknowledgement becomes success, confirmed rollback, a refund or an
automatic retry. The existing SQLSTATE classifier still describes pre-commit
driver failures; it does not resolve an uncertain commit outcome.

## Verification and limits

`tests/agents/test_postgresql_row_integrity.py` uses the existing Phase 170
synthetic fixtures and an inert projection-complete DB-API fake. It checks
foreign/contradictory documents, complete claim snapshot replay, native
primitive matrices, rollback nonmutation, cleanup uncertainty, tuple rows,
serialization costs and unchanged original golden IDs/digests. No PostgreSQL
engine, driver, target or provider is called by these tests.

The legacy migration marker, executable schema profile, receipt domains and
valid canonical bodies are unchanged. This guide does not claim a real server
executed the SQL, independent row authenticity, isolation against arbitrary
in-process callbacks, infrastructure qualification, deployment readiness or
new authorization. Live PostgreSQL conformance and operational owner decisions
remain separate requirements.
