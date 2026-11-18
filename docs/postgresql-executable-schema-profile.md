# Offline executable PostgreSQL schema profile

`postgresql_schema_profile` generates a deterministic SQL description for the
ten tables used by `PostgreSQLPersistenceSchedulerAdapter`. It has no connection,
driver, clock, credential, filesystem output, SQL application or service path.
The SQL has not been executed against PostgreSQL by this offline leaf. Generating
or parsing the description does not qualify a deployment or authorize a migration.

## Pure interface and addresses

```python
from sunderkey.postgresql_schema_profile import (
    PostgreSQLExecutableSchemaProfile,
    build_postgresql_executable_schema_profile,
    verify_postgresql_executable_schema_profile,
)

profile = build_postgresql_executable_schema_profile(schema_name="offline_fixture")
canonical_document = profile.to_json()
sql_text = profile.to_sql()
restored = PostgreSQLExecutableSchemaProfile.from_json(canonical_document)
owned = verify_postgresql_executable_schema_profile(restored)
```

The schema name is required. It is an exact native ASCII string matching
`[a-z][a-z0-9_]{0,62}`. System names beginning with `pg_` and `information_schema`
are rejected. Names are never normalized. An explicitly supplied `public` is not
a default or a claim that its ownership or privileges are safe.

Every table and foreign-key target is qualified with that selected schema. Index
names are fixed local names on qualified tables, not schema-qualified index names.
The selected schema must already exist under independently selected deployment
controls. No `CREATE SCHEMA`, `IF NOT EXISTS`, role, grant, RLS, extension,
partitioning, connection or search-path statement is generated. This is a fresh
table profile, not adoption or migration of an unknown existing schema.

`ddl_sha256` addresses the exact UTF-8 SQL bytes, including LF line endings and
the final LF. `profile_sha256` and the `PGS-` ID bind the complete description under
the new `sunderkey.postgresql-executable-schema-profile.v1` domain. These addresses
are unsigned content integrity, not evidence of execution, ownership or approval.

The frozen record is revalidated at every public export/verification boundary.
Native closed `from_dict` and exactly canonical `from_json` replay the fixed
templates from the selected schema. Changed SQL, scope, marker, effects or types
cannot be legitimized by recalculating their hashes. Dictionaries/lists exported
by `to_dict` are detached. This is not an arbitrary-Python sandbox or a guarantee
of atomic capture against concurrent caller mutation. A coherently different
valid profile remains a different unsigned description requiring external binding.

## Exact storage surface

| Table | Principal key and role |
| --- | --- |
| `schema_migrations` | Version key; legacy adapter compatibility marker |
| `aggregate_heads` | Tenant/aggregate key; current version and content hash |
| `resource_fences` | Tenant/resource key; existing token and epoch |
| `transaction_batches` | Tenant/idempotency key; assessment, scope and batch bytes |
| `outbox_events` | Tenant/event key; transaction or scheduler event bytes |
| `runtime_receipts` | Tenant/receipt key; addressed transaction receipt bytes |
| `schedules` | Tenant/schedule key; definition and cancellation flag |
| `occurrences` | Tenant/occurrence key and tenant/schedule/index uniqueness |
| `lease_snapshots` | Tenant/lease/version key and one active lease per occurrence |
| `scheduler_results` | Tenant/idempotency key; current `claim` result only |

The two parent foreign keys are tenant/schedule from occurrences to schedules and
tenant/occurrence from lease snapshots to occurrences. There is no circular
current-lease foreign key. Immediate, nondeferrable conflict keys match the
adapter's two `ON CONFLICT` clauses. The due index matches the pending/retry
claim order, and the partial unique index enforces one active occurrence lease.

The shared outbox deliberately has no transaction-batch foreign key. Its batch
ID can be a `PTB-` transaction or `DSL-` scheduler lease. Its tenant text supports
both existing opaque transaction tenant references and scheduler tenant IDs.
Completion, recovery and cancellation tables or new lifecycle APIs are not added.
The existing occurrence state vocabulary is retained without claiming those
PostgreSQL transitions are implemented. No outbox publisher is added.

Text identities have exact `pg_catalog."C"` collation. `active` and `cancelled`
are native BOOLEAN columns. Bounded scheduler counters are INTEGER columns;
aggregate head versions use signed 64-bit BIGINT with range 1 through
9,223,372,036,854,775,807. This is an explicit finite backend representation,
not full support for every unbounded Python integer accepted by the existing
pure transaction contract. That contract and its identities are unchanged.

JSON remains TEXT because current DB-API consumers call `json.loads` on native
strings. The SQL checks JSON object syntax only: they do not establish canonical
serialization, reject every duplicate JSON member, verify embedded hashes or
authenticate records. UTC metadata also remains TEXT. Guarded Gregorian integer
calendar checks reject invalid dates and component ranges without timestamp casts,
session timezone, DateStyle or a current clock. They require exact second-resolution
`YYYY-MM-DDTHH:MM:SSZ` text. Only `published_at` and the current occurrence's
`lease_id` are nullable. Database types/checks do not replace operation-specific
addressed parsing or authority checks. Existing adapter marker/context/fence/version/replay
checks remain unchanged; this leaf adds no whole-store source verifier.

## Legacy compatibility and activation boundary

The existing `POSTGRESQL_MIGRATION_PLAN` remains unchanged. Its statements are
prose and its SHA addresses a description. The profile retains that exact marker
as compatibility metadata; it does not relabel it as a SQL SHA or insert it into
`schema_migrations`. A trusted external setup would need to handle marker custody
separately. The current adapter checks that legacy marker, not this new profile
digest, before its operations.

The adapter's queries remain unqualified. Qualified DDL alone cannot make them
select the intended schema. Connection-factory/schema-resolution activation and
trusted search-path ownership are outside this leaf. No production database,
credential, role, topology, region, backup, failover or D014 deployment selection
is inferred. The approved D006 boundary keeps SQLite as the current local
single-control-plane authority.

## Verification limits

Tests inspect deterministic SQL/profile bytes, native bounded replay, the actual
adapter's literal table/column/conflict-key inventory, fixed constraints/indexes,
known UTC predicate structure and both outbox producer families. Existing Phase170
test assertions remain applicable. Their cursor exposes selected key projections
and the original lease-snapshot query, but interprets operation tags, not
PostgreSQL grammar or engine behavior. These checks do not prove executable engine
syntax, effective constraints/query plans, serializable races, SKIP LOCKED, RLS,
grants, failure recovery, migration safety or production latency/qualification.

The raw SQL bound is 128 KiB; canonical JSON intake is bounded to 256 KiB before
decoding. Closed native shapes reject aliases, booleans as integer metadata,
floats/nonfinite numbers, duplicate keys, oversized integers and malformed Unicode.
Malformed inputs are not normalized or automatically readdressed into acceptance.
All declared effects remain `none`.

Technical references are the official PostgreSQL 18 documentation:

- [CREATE TABLE](https://www.postgresql.org/docs/18/sql-createtable.html)
- [CREATE INDEX](https://www.postgresql.org/docs/18/sql-createindex.html)
- [Schemas and search path](https://www.postgresql.org/docs/18/ddl-schemas.html)
- [Numeric types](https://www.postgresql.org/docs/18/datatype-numeric.html)
- [Collation](https://www.postgresql.org/docs/18/collation.html)
- [Regular-expression constraint escapes](https://www.postgresql.org/docs/18/functions-matching.html)
