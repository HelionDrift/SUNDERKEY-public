# End-to-End Conformance Harness

`sunderkey.end_to_end_conformance` provides a deterministic, repository-only
coordinator for checking the control continuity of a complete SUNDERKEY
workflow. It uses injected step adapters and content-addressed observations.
It does not connect to or operate any live component.

## Ordered chain

The coordinator fixes the following order:

1. Service intake
2. Scheduler dispatch
3. Action admission
4. Specialist execution
5. Evidence recording
6. Finding validation
7. Reporting
8. Activation review
9. Activation
10. Cleanup and restoration
11. Rollback verification

Every successful stage advances one aggregate version. Each observation binds
the tenant, context, scope, mission, operator, plan, active fence, expected
version, idempotency key, prior stage, prior custody entry, stage artifacts,
budget use, and stage-specific control links. These bindings prevent evidence
from one mission or execution context from being substituted into another.

## Injection boundary

`run_conformance` accepts a mapping of stage names to adapters. An adapter only
receives a `StageRequest` and returns a `StageEvidence` object or its mapping.
This makes deterministic offline fakes possible without importing deployment,
database, browser, scanner, credential, or network clients.

The coordinator invokes adapters one at a time in the fixed order. It stops at
the first absent adapter, adapter error, invalid observation, failed stage,
skipped stage, review failure, budget violation, or continuity violation. A
later adapter is never invoked after that point.

`assess_conformance` validates evidence that was collected elsewhere without
invoking an adapter. Both entry points return a content-addressed receipt and a
content-addressed gap report.

## Fail-closed controls

The harness rejects or reports:

- Missing, duplicate, extra, or reordered stages
- Altered content addresses and noncanonical records
- Tenant, context, scope, mission, operator, or plan rebinding
- Stale or substituted fence data
- Stale aggregate versions
- Broken prior-stage or custody links
- Replaced idempotency keys
- Per-stage or cumulative budget overruns
- Missing, rejected, or nonindependent reviews
- Failed or skipped required stages
- Missing cleanup, activation, restoration, or rollback links

Failed and skipped stages do not advance the aggregate version. They require a
bounded reason code, produce a nonconformant result, and stop collection.

## Review requirements

Independent review is mandatory for action admission, finding validation,
activation review, cleanup and restoration, and rollback verification. The
review binds the exact stage observation hash. The reviewer cannot be the
bound operator or the stage adapter identity, and the decision must be
`accepted`.

The activation observation must link to the activation review. Cleanup and
restoration must link to the plan cleanup obligation and the specialist
execution observation. Rollback verification must link to the activation
observation, cleanup and restoration observation, and rollback policy.

## Budget and custody behavior

Plans bind ceilings for requests, tokens, elapsed milliseconds, and evidence
bytes. Each adapter reports nonnegative use. The coordinator checks both the
stage against its remaining allowance and the cumulative total against the
plan ceiling.

Every stage supplies a sorted, unique list of artifact content addresses. The
stage custody address covers those artifacts, the stage name, and the previous
custody address. A changed artifact or prior custody link therefore changes
the observation and evidence content addresses.

## Receipt semantics

A `conformant` receipt means only that all offline adapter observations passed
this contract. A `nonconformant` receipt references an exact gap report. Both
records include `qualification_effect: none` and state the proof scope as
`repository_only_offline_adapter_conformance`.

The JSON Schema at
`registry/schemas/end-to-end-conformance-receipt-v1.schema.json` validates the
plan, stage evidence, gap report, and receipt envelopes.

## Explicit limits

This harness does not:

- Open network connections
- Access credentials or environment secrets
- Discover files or targets
- Execute a target or specialist tool
- Create or alter infrastructure
- Deploy a service or worker
- Grant authorization
- Qualify or promote an expert
- Prove a live service, scheduler, database, evidence store, finding pipeline,
  report pipeline, activation path, cleanup path, or rollback path

Live conformance requires separately authorized infrastructure, real adapters,
independent evidence capture, and independent human review. Those actions are
outside this repository-only contract.
