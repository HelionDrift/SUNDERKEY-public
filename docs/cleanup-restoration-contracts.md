# Cleanup and Restoration Contracts

This increment defines the repository-only X1.12 cleanup and restoration
coordination boundary. It provides immutable plans, externally supplied
observations, and fail-closed completion assessments. It does not contact a
target, execute cleanup, remove artifacts, restore state, persist records,
grant authorization, or change qualification state.

## Contract sequence

1. `CleanupRestorationPlan` binds one tenant, mission, scope digest, authorized
   action digest, worker identity and profile digest, target digest, exact
   contract version, and approval evidence.
2. `TargetStateObligation` fixes the intended state of each affected artifact as
   absent, restored, or retained. It binds the target, baseline, and required
   verification evidence by digest.
3. `CleanupStep` orders removal, restoration, verification, and release work.
   Every step has a timeout, evidence requirements, explicit failure behavior,
   and any rollback or compensating actions needed after failure.
4. `CleanupObservation` records evidence supplied by an observer who is
   independent from the bound worker. It also records residual artifacts and
   their unresolved, separately accepted, or separately quarantined status.
5. `assess_cleanup_completion` compares the plan and observation and emits a
   content-addressed `CleanupCompletionAssessment` for an independent reviewer.

Every top-level record includes `effects` whose values are all `none`. A record
is descriptive evidence only.

## Fail-closed completion

The assessment status is `contract_complete_unverified` only when all supplied
records have identical tenant, mission, scope, action, worker, worker profile,
target, version, plan identity, and plan digest bindings. Every declared step
must be observed in its specified order, must succeed, and must provide exact
required evidence. The reviewer must match the review binding and must be
independent from the worker and observer.

The status is `incomplete` when any step is missing, reordered, failed, timed
out, not observed, or lacks exact evidence. Unobserved required compensation,
plan expiration, any residual artifact, and any unresolved residual risk also
force an incomplete result. A separately accepted or quarantined residual still
prevents the cleanup record from claiming complete removal. Separate authority
does not silently widen the cleanup plan.

`contract_complete_unverified` means only that caller-supplied records are
internally consistent with this contract. It does not mean cleanup ran, state
was restored, a target was changed, evidence is authentic, signatures were
validated, or an environment is safe.

## Ordering, rollback, and timeout behavior

Steps use contiguous sequence numbers beginning at one. Every target-state
obligation must have at least one ordered step, and every step must refer to a
declared obligation. Rollback and compensate-then-halt behavior require at
least one content-bound compensating action. A failed or timed-out step stays
incomplete even when compensation is observed because compensation is not
proof that the desired target state was reached.

Step observations use explicit terminal outcomes. Successful observations need
evidence. Failed and timed-out observations are retained for review rather than
converted into success. Timestamps are canonical UTC and completion cannot
precede start.

## Residual risk

`ResidualArtifact` identifies the expected content and any observed content.
An unresolved residual cannot claim a separate authority. Accepted and
quarantined dispositions require an opaque separate approval reference. These
records expose risk to later governance workflows without granting approval or
performing quarantine.

## Serialization and schema

Plans, observations, and assessments have deterministic canonical JSON,
content-derived identifiers, and SHA-256 content addresses. Deserialization
rejects unknown fields, altered addresses, moving version aliases, malformed
timestamps, duplicate references, invalid ordering, and any change to the
no-effect boundary.

`registry/schemas/cleanup-restoration-contract-v1.schema.json` is a strict Draft
2020-12 schema. Python constructors remain authoritative for cross-record
context equality, ordering, independence, exact evidence comparison, content
address verification, time relationships, and completion assessment.

## Infrastructure boundary

Operational completion of X1.12 still needs separately authorized execution,
target-specific cleanup adapters, state capture, compensating-action runners,
evidence collection, trusted identity and signature verification, durable
storage, and independent human review. Those systems can supply records to
this contract. This module neither performs nor authorizes those activities.
