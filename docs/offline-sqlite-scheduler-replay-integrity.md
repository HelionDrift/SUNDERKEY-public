# Offline SQLite scheduler replay integrity

The local-development SQLite scheduler returns an immutable cached result only
when it still matches the requested operation context. This is a storage replay
boundary, not current authorization, provider execution, or production readiness.
The PostgreSQL adapter and its qualification boundaries are unchanged.

## Exact cached result checks

The existing tenant-scoped `scheduler_results` row is checked in the same SQLite
write transaction as the public operation. Before a cached result is returned:

1. The stored result kind must match the operation.
2. The existing `result_sha256` must reproduce the original `result_json` text.
3. That text must be canonical JSON without discarded duplicate fields.
4. The existing typed lease, completion, or cancellation parser must replay its
   addressed identity and content. Its canonical reconstruction must reproduce
   the complete stored document, including JSON scalar types.
5. The result must match every recoverable immutable caller field below.

Every operation also matches the result's `tenant_id` and `idempotency_key`.

| Public operation | Additional exact context |
| --- | --- |
| `claim_due` | Claim transition, schedule ID, worker reference |
| `heartbeat` | Heartbeat transition, lease ID, prior expected lease version plus one, exact fence epoch |
| `complete` | Lease ID, expected lease version, expected fence epoch, completion status, canonical evidence digest list |
| `cancel_occurrence` | Occurrence target, occurrence ID, reason code |
| `cancel_schedule` | Schedule target, schedule ID, reason code |

Heartbeat and completion retry versions and fences must be native positive
integers within the existing contract bound. Boolean, float, and integer-subclass
aliases cannot satisfy the retry comparison. Valid completion enum and string
statuses remain interchangeable. Evidence digests retain the existing sorted,
unique normalization; changing their input order is not a conflict, while
duplicates or malformed digests are invalid.

Both cancellation operations retain the existing `cancellation` result kind.
Their distinct typed targets prevent an occurrence cancellation from being
returned as a schedule cancellation, or the reverse.

## Historical retry and failure boundaries

An exact retry can return the original result after completion, cancellation,
lease expiry, or process restart. The retry's `claimed_at`, `observed_at`, or
`requested_at` is not compared with the original result's timestamp. No missing
prior state is reconstructed, no original result is overwritten, and replay
does not enqueue another outbox event or settle the operation again. This does
not renew a lease or establish current scope, authority, or execution eligibility.

Changed immutable context raises `IdempotencyConflict`. Invalid cached raw hash,
canonical JSON, or canonical reconstruction raises `PersistenceRuntimeError`;
the existing typed contract parsers also retain their validation errors. Failed
checks leave the logical store unchanged through transaction rollback. There is
no automatic retry or fallback.

The stored hash and addressed metadata detect corruption and contradiction.
They do not independently authenticate a writer or make a coherently replaced
document signed evidence. This repair does not claim containment of arbitrary
in-process callbacks or concurrent mutation of caller-owned Python objects.

## Compatibility and regression evidence

The existing SQLite schema, migration identity, scheduler hash domains, output
IDs, and native valid result bytes are unchanged. No historical rows are
readdressed and no migration is introduced.

`tests/agents/test_sqlite_scheduler_replay_integrity.py` uses only synthetic
temporary local SQLite databases and the existing Phase166 schedule fixture. It
checks native changed-field conflicts, both cancellation target switches,
independently readdressed cached tenant and key substitutions, raw hash mismatch,
noncanonical and duplicate JSON, equal-value JSON numeric aliases, stable golden
result hashes, later post-settlement retries, tenant isolation, and unchanged
logical snapshots. The existing Phase164 scheduler contracts, Phase166 runtime,
and Phase170 PostgreSQL controls remain adjacent compatibility evidence, not
live database or provider qualification.
