# Disaster Recovery Proof Contracts

This increment defines the repository-only disaster recovery proof boundary for
roadmap package S6.9. It provides deterministic records and a fail-closed
assessment function. It does not create backups, restore data, delete data,
access keys, write persistence, contact a network, deploy services, grant
authority, or change qualification state.

## Contract sequence

1. `RecoveryObjective` fixes the tenant, system, exact system and objective
   versions, RPO, RTO, maximum backup age, required artifacts, required event
   head, required evidence, timestamp, and signed reviewer binding.
2. `BackupManifest` binds one backup identity and version to signed verification,
   an opaque key descriptor, an unambiguous registry rollback lineage, custodied
   artifacts, a verified event store checkpoint, and custodied evidence.
3. `RestorationRehearsalPlan` binds the objective and backup by identity and
   digest. It repeats every key, registry, artifact, event, evidence, tenant,
   system, version, timestamp, executor, and independent reviewer boundary.
4. `ObservedRestorationResult` records externally produced observations. A
   restored-state claim requires a signed observation. The record captures the
   exact restored key descriptor, registry rollback lineage, artifacts, event
   checkpoint, evidence, timing, observer, and any unrecoverable gaps.
5. `assess_recovery_readiness` checks every binding and calculates observed RPO,
   observed RTO, and backup age. It emits a content-addressed
   `RecoveryReadinessAssessment` with a signed independent reviewer binding.

All top-level records carry `effects` set to `none` for authorization, backup,
credential or key access, deletion, deployment, network, persistence,
qualification, and restore.

## Fail-closed rules

The constructors reject unknown fields during deserialization, malformed or
moving versions, invalid timestamps, duplicate references, incomplete custody
bindings, ambiguous registry parentage, inconsistent time order, altered
content addresses, mutated effect declarations, and restored-state claims that
lack a signed observation.

The assessment requires one tenant, system, and exact system version across all
records. It also requires exact objective, backup, plan, result, key, registry,
artifact, event, evidence, timestamp, and reviewer bindings. An assessment
cannot be performed by the objective reviewer, rehearsal executor, or result
observer. The readiness reviewer must be the independent reviewer identified in
the rehearsal plan.

The result is `not_ready` when any of the following applies:

- backup verification failed or its event chain is unverified;
- the verified backup is older than the objective permits;
- the key descriptor differs across backup, plan, and result;
- registry snapshot or rollback lineage differs or is ambiguous;
- required artifact content or custody does not match;
- event store head, sequence, digest, or verification does not match;
- required evidence content or custody does not match;
- an unrecoverable gap exists;
- a signed restored-state observation is absent;
- the observed recovery point differs from the planned recovery point;
- the planned recovery point is newer than the backup creation timestamp;
- observed RPO or RTO exceeds the objective.

A passing record is `contract_ready_unverified`. This means supplied evidence is
internally consistent with the repository contract. It does not mean a backup
exists, a restoration occurred, the signature is trusted, the service is
qualified, or the recovery objective is satisfied in a live environment.

## Recovery calculations

Observed RPO is the interval from the plan's simulated failure timestamp back to
the result's restored recovery point. Observed RTO is the interval from the
simulated failure timestamp to observed completion. Backup age is the interval
from signed backup verification to assessment. Negative intervals are rejected.

## Unrecoverable gaps

`UnrecoverableGap` records missing, unavailable, digest-mismatched, or
custody-broken artifacts, events, evidence, keys, and registry snapshots. Each
gap binds the expected reference and digest, any observed reference and digest,
detection time, reason, identity, and content address. Gaps are evidence of a
failed recovery proof and never authorize repair, deletion, or restoration.

## Schema

`registry/schemas/disaster-recovery-contract-v1.schema.json` is a strict Draft
2020-12 schema for all top-level records and their nested bindings. Every object
rejects additional properties. The Python constructors remain authoritative for
cross-record equality, independence, chronology, content-address, continuity,
RPO, RTO, and freshness checks that JSON Schema cannot express by itself.

## Infrastructure boundary

Operational completion of S6.9 still requires infrastructure-backed backup
creation, protected retention, organization key management, registry snapshot
capture, event store verification, isolated restoration rehearsal, signed
observation collection, and independent review. Those activities must occur in
an approved environment and supply records to this contract. This module does
not perform or authorize them.
