# Durable Scheduler Contracts

This increment defines the repository-only contract boundary for roadmap package S6.3 and
scheduled assessment semantics. It is deliberately not a live scheduler. It creates immutable,
content-addressed records that a future durable runtime can persist and apply transactionally.

## Scope

The contract provides:

- tenant-bound schedule definitions with exact definition versions
- bounded interval recurrence with start and optional end timestamps
- skip, fire-once, and bounded catch-up misfire policies
- deterministic due-occurrence materialization
- per-evaluation occurrence limits and schedule concurrency limits
- fenced lease claims with exact occurrence versions
- immutable heartbeat snapshots with exact lease versions
- bounded lease durations and explicit clock-skew tolerance
- bounded exponential retry plans and retry budgets
- completion observations that resolve to completed, retry planned, cancelled, or dead lettered
- expired-lease recovery that advances the fence exactly once
- schedule-level and occurrence-level cancellation records
- idempotent exact replay with conflict rejection
- strict JSON round trips and content-tamper detection

The implementation is in `src/sunderkey/durable_scheduler_contracts.py`. The strict union schema
is `registry/schemas/durable-scheduler-contract-v1.schema.json`.

## Record flow

1. `RetryBackoffPlan` sets the maximum attempts, retry-unit budget, retry cost, and deterministic
   delay function.
2. `ScheduleDefinition` binds recurrence, lease, misfire, retry, tenant, scope, authority-evidence,
   and assessment-template inputs.
3. `derive_due_occurrences` evaluates only caller-supplied time and prior materialized indices. It
   returns zero or more `DueOccurrence` records within schedule bounds.
4. `claim_due_occurrence` creates a `DurableLease` claim when the expected occurrence version,
   fence, attempt, concurrency, clock-skew, and duplicate-active-lease checks pass.
5. `heartbeat_lease` creates the next immutable lease snapshot. It requires the exact prior lease
   version and fence and must advance expiration within the configured duration.
6. `observe_completion` binds an outcome to the exact lease digest, lease version, fence,
   occurrence version, and retry plan. It does not execute a retry.
7. `plan_expired_lease_recovery` accepts only a lease expired beyond the clock-skew allowance. It
   rejects leases with completion observations and produces a requeue or dead-letter plan.
8. `create_cancellation_record` produces a versioned intent and lists active lease snapshots that a
   future transaction must revoke.

## Required transactional runtime behavior

This package does not implement storage. A future runtime should map these records to the
persistence port and transaction-batch contracts with the following atomic checks:

- compare every `expected_version` to the stored aggregate version
- require every `new_version` to be exactly one greater
- compare the lease fence before heartbeat, completion, cancellation, or recovery
- use the record idempotency key as a unique tenant-scoped binding
- reject idempotency-key reuse with different canonical content
- allow only one current unexpired lease per occurrence
- count current unexpired schedule leases before admitting a claim
- append the immutable record and update its projection in one transaction
- place externally visible events in the transactional outbox in the same commit

PostgreSQL is the production target described by the persistence port contracts. SQLite remains a
development and local-test adapter. Neither adapter is invoked by this module.

## Failure-closed rules

The contract rejects:

- an occurrence outside its schedule or tenant
- a future occurrence evaluated before its nominal timestamp
- materialization above schedule or per-evaluation limits
- duplicate materialized indices
- claim attempts beyond the retry plan
- a claim before the allowed clock-skew boundary
- a claim or heartbeat longer than the configured lease duration
- an active duplicate lease for the same occurrence
- a stale lease version, occurrence version, or fence
- a heartbeat that does not advance expiration
- completion after the lease expiration plus the clock-skew allowance
- more than one distinct completion for a lease snapshot
- recovery before expiration plus the clock-skew allowance
- recovery of a completed lease
- a retry that would exceed attempt or retry-unit budgets
- a version transition that does not increment exactly once
- idempotency-key rebinding
- unknown fields, unknown record types, altered digests, altered identifiers, and noncanonical order

## Effect boundary

Every serialized record carries the same effect declaration:

- authorization: none
- clock: caller supplied
- execution: none
- network: none
- persistence: none
- processes: none
- scheduling: none
- target actions: none
- threads: none

The module does not read wall-clock time, start a timer, create a process or thread, open a network
connection, persist a record, authorize an assessment, invoke a worker, or interact with a target.
The authority evidence digest is an immutable reference only. A live runtime must independently
verify current scope and authority before it admits any assessment work.

## Qualification status

This increment establishes deterministic contracts and focused tests. It does not complete S6.3
operational qualification. Qualification still requires a production adapter, transactional
storage, multi-worker contention tests, crash recovery, clock-skew tests across hosts, failover,
observability, capacity evidence, and controlled assessment-canary evidence.
