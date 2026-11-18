# Detection correlation runtime

## Purpose

The detection correlation runtime deterministically evaluates already imported,
normalized defender telemetry against already recorded execution evidence. It
turns expected detections, negative controls, and false-positive controls into
content-addressed validation results, coverage gaps, root-cause hypotheses,
tuning recommendations, and an independent review plan.

This increment is repository-only and nonqualified. It does not query a SIEM,
collect telemetry, contact a provider, write a detection rule, authorize an
action, execute against a target, or change qualification state.

## Bound inputs

Each request binds one tenant, engagement, scope digest, and custody policy
digest. Its execution reference carries the immutable execution result digest,
action digest, evidence manifest digest, durable artifact reference, time
bounds, and durable custody evidence. Every normalized signal reference repeats
the same context and custody policy, then identifies the upstream source
binding, normalized event, raw event, artifact, classification, and event time.

The runtime rejects cross-tenant, cross-engagement, cross-scope, and
cross-custody inputs before correlation. It also rejects unverified custody,
unredacted signal references, future-dated inputs, stale normalized inputs, and
execution evidence that is not complete at evaluation time.

## Correlation model

Expected detections specify an operation code, accepted telemetry domains,
accepted outcomes, an inclusive observation window, and a minimum count.
Negative controls specify a signal that should be absent or remain under a
strict count. False-positive controls add a content-addressed baseline evidence
reference and a maximum accepted signal count.

Correlation is a pure function over those references. Matching uses only the
normalized operation code, telemetry domain, outcome where applicable, and
event timestamp. Input order does not affect any derived identity.

For each control, the runtime emits a content-addressed result with exact signal
membership, observed count, threshold, state, and reason code. Failed controls
produce three separate content-addressed findings:

1. A coverage gap that records what was not validated.
2. A root-cause hypothesis that distinguishes missing source telemetry,
   window mismatch, detector mapping mismatch, or detector overmatching.
3. A tuning recommendation that remains subject to independent review.

The output is an assessment plus a review plan requiring separate independent
control and independent assurance roles. The review plan is pending only. It
does not claim that either review occurred.

## Replay and tamper controls

Normalized event identity, normalized event digest, source event reference,
and raw event digest must each be unique inside a request. A caller can provide
sorted consumed event digests from an earlier completed assessment. Reuse of
any active digest fails as replay. Request, execution, signal, result, finding,
assessment, review plan, and bundle identities are derived from canonical JSON.
Parsing reconstructs the request and rejects any content-address mismatch,
unknown field, or effect escalation.

## Strict budgets

The request fixes ceilings for expected detections, observed signals, negative
controls, false-positive controls, total control results, derived findings,
window duration, and source age. Budget exhaustion fails closed. There is no
partial assessment and no silent truncation.

## Integration boundary

Callers construct `ExecutionEvidenceReference` from a verified execution result
and durable evidence manifest. They construct `NormalizedSignalReference`
records from verified normalized telemetry events and source binding metadata.
The correlator does not dereference those records or fetch missing data.

The public module surface is:

- `CorrelationBudget`
- `ExecutionEvidenceReference`
- `NormalizedSignalReference`
- `ExpectedDetection`
- `NegativeControl`
- `FalsePositiveControl`
- `CorrelationRequest`
- `ControlValidationResult`
- `DerivedFinding`
- `CorrelationAssessment`
- `IndependentReviewPlan`
- `CorrelationBundle`
- `correlate_detection_controls`
- `parse_contract`

The schema at
`registry/schemas/detection-correlation-runtime-v1.schema.json` validates both
caller-authored requests and complete derived bundles. Schema validity does not
replace the semantic and content-address checks performed by the module.

## Explicit limitations

This module supplies deterministic correlation behavior only. Production use
still requires approved telemetry sources, live collection infrastructure,
durable evidence storage, source-specific query implementations outside this
module, independent reviewers, operational tuning approval, and signed
qualification evidence. No output from this module establishes production
readiness, detector efficacy, compliance, or qualification.
