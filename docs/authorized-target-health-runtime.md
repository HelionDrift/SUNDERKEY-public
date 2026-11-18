# Authorized target-health observation runtime

## Purpose

The target-health runtime is a repository-only, fail-closed aggregation
boundary. It combines evidence from the authorized HTTP, browser, and
target-session runtimes into one content-addressed point-in-time health
receipt. It performs no target interaction and includes no network client,
browser, credential provider, probe, subprocess, payload, or deployment
adapter.

The runtime does not grant assessment authority and does not qualify a
deployment. Its authority and qualification effects are fixed to `none`.
A completed receipt proves only that the supplied content-addressed evidence
passed the local contract at the recorded instant.

## Evidence model

Every completed observation requires all of these inputs:

1. A cryptographically verified `VerifiedAssessmentScope`.
2. An `ExecutionRequest` and admitted `AdmissionReceipt` with exact scope,
   target, session, lease, fence, execution-policy, and payload bindings.
3. An `AuthorizedTargetHealthPolicy` bound to the exact execution binding,
   HTTPS target, read-only method, technique, impact tier, freshness limits,
   latency thresholds, and aggregation budgets.
4. Fresh `ScopeBudgetState`, `TargetHealthBudgetState`,
   `TargetHealthSafetySnapshot`, and `ClockObservation` values. Completed
   receipts embed the exact safety and budget attestation bodies alongside
   their content digests.
5. At least one content-addressed receipt from each authorized boundary:
   HTTP, browser, and target session.
6. Exactly one content-addressed `TargetHealthObservation` for each required
   health dimension.

The accepted dimensions are reachability, latency, authentication
continuity, expected WAF control state, and service health. This closed set
prevents a caller from relabeling unrelated evidence as health evidence.

## Source composition

The runtime accepts only actual receipt objects from these modules:

* `authorized_http_runtime`
* `authorized_browser_runtime`
* `authorized_target_session_runtime`

It runs each receipt through that module's strict verifier and requires exact
scope and execution-binding equality. A source must record that its injected
boundary was called. A pre-call rejection cannot become target-health
evidence. Source receipts, observations, and their evidence digests must all
be fresh under the runtime policy.

Each health observation binds its dimension, state, closed detail code,
source receipt identity and digest, external evidence digest, observation
time, expiry, and optional latency value. The source vocabulary is restricted
by dimension. Authentication continuity, for example, can use only browser or
target-session evidence. WAF state can use only HTTP or browser evidence.

The WAF dimension records only whether an expected control state was observed
at one instant. It does not claim detection efficacy, bypass resistance, or
control ownership.

## Fail-closed behavior

The runtime returns a deterministic rejected receipt when any required
contract fails, including:

* scope, target, session, lease, fence, policy, request, or admission mismatch;
* a non-admitted execution request;
* an expired scope or out-of-scope URL, method, technique, or impact tier;
* cancellation, emergency stop, or a non-healthy runtime safety state;
* stale, future, expired, missing, duplicated, or unreferenced attestations;
* source receipts with no boundary observation;
* source kinds that are invalid for a health dimension;
* request, evidence-byte, observation, or source-receipt budget exhaustion;
* latency state that is more favorable than the configured thresholds allow;
* a healthy signal derived from a non-completed boundary receipt;
* contradictory reachability and service-health claims; or
* altered content addresses, unknown fields, duplicate JSON keys, non-ASCII
  JSON, floating-point values, or non-canonical JSON.

A rejected receipt contains no source receipts or health observations and has
no overall-health claim.

## Health result semantics

The overall result is the least favorable state among the five required
dimensions. The closed order is healthy, degraded, then unhealthy. The
receipt constructor recomputes this result and rejects a more favorable
aggregate claim.

Latency is checked directly against the policy thresholds:

* at or below the healthy threshold is healthy;
* above the healthy threshold and at or below the degraded threshold is
  degraded; and
* above the degraded threshold is unhealthy.

The other dimensions use closed state and detail-code pairs. Arbitrary detail
text is not accepted.

## No injected probe in version 1

Version 1 deliberately accepts explicitly attested boundary observations
instead of invoking a health probe. This choice keeps the aggregation step
free of target effects and prevents an aggregation retry from becoming an
uncontrolled second probe. A future probe adapter would require its own
admitted execution request, one-call enforcement, transport isolation,
timeout controls, byte ceilings, and independent qualification before its
receipt could be admitted here.

## Receipt and verification

`TargetHealthReceipt` records exact scope, execution request, admission,
execution policy, runtime policy, execution binding, safety attestation,
budget state, source receipt references, and health observations. A completed
receipt is invalid unless the embedded safety and budget attestations exactly
match their digests, execution request, and binding, are current at the receipt
time, and report healthy, uncanceled safety state. It records
all external-effect flags as false because this module performs only local
aggregation. The source receipts retain the evidence of effects performed by
their separate injected boundaries.

`verify_target_health_receipt` accepts canonical ASCII JSON or an exact object.
It rejects duplicate or unknown keys, floating-point and non-finite values,
altered observation, source-reference, or receipt content addresses, invalid
terminal-state combinations, inconsistent overall health, and any authority,
qualification, network, browser, authentication, or external-call overclaim.

The companion JSON Schema uses Draft 2020-12 and forbids additional
properties throughout.

## Deployment obligations

Repository tests use deterministic local fixtures only. A real deployment
must provide qualified HTTP, browser, target-session, clock, safety, scope,
budget, evidence-custody, and admission infrastructure. It must also enforce
network isolation, TLS validation, credential custody, cancellation,
emergency stop, rate limits, timeouts, cleanup, monitoring, reviewer access,
retention, and independent qualification. None of those deployment
properties are claimed by this module.
