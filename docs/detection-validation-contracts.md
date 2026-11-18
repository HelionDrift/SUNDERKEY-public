# Detection and Control Validation Contracts

The Phase 163 contract layer closes repository-only portions of roadmap packages D8.1 through D8.4. It normalizes already retained telemetry references, correlates them with one exact execution, evaluates expected detections and controls, records coverage gaps, and produces replay-safe validation plans. It does not collect telemetry or perform a replay.

## Boundary

`sunderkey.detection_validation_contracts` is deterministic, immutable, content addressed, and infrastructure independent. It has no clients for networks, targets, telemetry platforms, detection systems, credential systems, or deployment systems. Every contract and replay plan declares these effects as `none`:

- authorization
- collection
- detection system writes
- network activity
- qualification
- target actions

An accepted record is evidence about caller-supplied references. It is not permission to test a target, assurance that an alert exists, or qualification evidence by itself.

## Exact execution binding

Every validation binds one assessment, execution, executor, action tier, signed scope digest, action digest, evidence digest, and execution interval. Telemetry, detector assessments, control outcomes, coverage gaps, and two independent validation records must agree with the exact scope, action, and evidence digests.

The two validators have separate `independent_control` and `independent_assurance` roles. They must be different people or profiles, and neither may be the executor. Review artifacts are content-addressed and their decision must be `accepted` before the aggregate contract can be built.

## Telemetry correlation

A telemetry observation reference contains only redacted metadata and digests. Durable verified custody is mandatory. The observation must:

- use one of the network, identity, cloud, application, endpoint, or data domains;
- name a source system and detector;
- name an event, alert, investigation, or prevention observation kind;
- fall inside the bounded correlation window;
- meet the expectation's maximum detection latency;
- remain retained beyond the evaluation time;
- carry exact scope, action, and evidence hashes.

Missing custody, stale retention, out-of-window observations, unaccepted observation kinds, and detector or domain mismatches fail closed.

## Detection and control outcomes

Each control objective identifies the material path, control family, expected effect, configuration digest, required telemetry domains, and exact expectation IDs. Each expectation has exactly one detector assessment. Dispositions are true positive, false positive, false negative, or inconclusive.

Control outcome state and false-positive and false-negative counts are derived from those dispositions. A caller cannot label a failed or contradictory result as effective. Required false negatives need an explicit coverage gap, such as missing telemetry, detection, investigation, or prevention. Other supported gaps identify unmapped detectors and unverified controls.

## Replay-safe plans

Replay plans bind the complete validation contract and the proposed control-change digest. Their content address and idempotency key make identical plans stable across retries. Offline evidence replay is restricted to R0. A live replay request is accepted as an inert plan only when it declares `separately_authorized_runtime` and supplies an external authorization digest. The digest is a reference, not authority granted by this module.

The plan still has no network or target effect. Separate runtime authorization, transport, telemetry integration, stop controls, monitoring, evidence custody, and independent operational review remain infrastructure requirements.

## Verification

The Python loader enforces cross-record semantics and recomputes content addresses. `registry/schemas/detection-validation-contract-v1.schema.json` independently verifies the serialized contract shape. Focused tests cover round trips, tampering, schema boundaries, custody, freshness, correlation windows, latency, role separation, hash exactness, contradictory outcomes, coverage gaps, and replay authorization boundaries.
