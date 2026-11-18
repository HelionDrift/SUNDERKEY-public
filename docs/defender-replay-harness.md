# Defender Replay Harness

The defender replay harness provides a deterministic, repository-only way to
replay sanitized assessment findings against sanitized defensive telemetry. It
calculates coverage and latency observations while preserving the distinction
between missing source data and an observed detection failure.

## Boundary

The harness accepts caller-supplied objects only. It has no network client,
provider integration, credential resolver, filesystem discovery, source write,
target action, qualification effect, or deployment effect. A replay receipt is
an offline observation. It does not demonstrate external defensive
effectiveness.

Every request binds one tenant, engagement, replay context, scope digest,
corpus digest, and provenance policy digest. Assessment evidence, findings,
telemetry fixtures, and availability declarations must match that context.
Cross-tenant, cross-engagement, cross-context, cross-scope, and cross-corpus
inputs fail closed.

## Inputs

`ReplayContext` defines the immutable isolation boundary.

`AssessmentEvidenceBinding` binds a sanitized assessment and its evidence
manifest to durable custody. Each finding fixture must reference this binding.

`EvaluationContractBinding` records the evaluation program, run plan, scoring
policy, corpus assembly, evaluator, and replay producer. Evaluator and producer
identities must differ.

`DetectionCorrelationBinding` records the exact correlation bundle,
correlation assessment, pending review plan, and consumed-event manifest used
as replay context. Its tenant, engagement, context, and scope must match the
replay boundary.

`FindingFixture` and `TelemetryFixture` are content-addressed. Both bind their
source material and provenance with SHA-256 digests. The fixtures carry only
sanitized references and timestamps, never source payloads or credentials.
Every telemetry fixture also binds the exact finding fixture that it can
support, which prevents one signal from being reused across unrelated findings.

`SourceAvailability` explicitly declares whether a telemetry domain has data
for a time window. Availability evidence is also bound by digest. Replay does
not infer availability from an empty fixture list. A missing signal is a
`failed_detection` only when every required domain has uninterrupted declared
availability from the finding occurrence through the replay cutoff. A detected
signal needs uninterrupted availability through its observation time. Gaps or
declared absence produce `absent_source_data`, and overlapping windows fail
closed. Findings and telemetry observed after the replay cutoff are rejected.
The replay cutoff must also be at or after every detection latency objective;
an unfinished observation window cannot be scored as a failure.

`DetectionExpectation` binds one finding fixture to an expected operation,
one or more telemetry domains, and a maximum latency objective.

## Observation states

The harness produces one of four states for every expectation:

* `detected_within_objective`: the earliest matching telemetry fixture met the
  latency objective.
* `detected_late`: matching telemetry exists, but it missed the latency
  objective.
* `failed_detection`: all required source domains were available, but no
  matching telemetry fixture was observed.
* `absent_source_data`: at least one required source domain was explicitly
  unavailable, so the expectation cannot be evaluated as a detection failure.

Only evaluable expectations contribute to detection and objective coverage.
Coverage uses integer basis points. Latency is measured in whole seconds from
the finding occurrence to the earliest matching telemetry observation. If no
expectation is evaluable, coverage is unknown rather than zero. If no detection
is observed, latency is unknown.

## Receipt integrity

The request, fixtures, assessment binding, observations, reviews, and receipt
use deterministic canonical JSON and SHA-256 content addresses. Receipt parsing
reconstructs all invariants and rejects unknown fields, modified metadata, and
content-address mismatches. Secret-like material is rejected before hashing.

The receipt records:

* the bound tenant, engagement, context, scope, corpus, and provenance policy;
* assessment and evaluation contract identities;
* the detection correlation bundle and binding identities;
* an input manifest digest;
* per-control coverage and latency observations;
* aggregate counts and integer coverage values;
* `repository_only_nonqualified` runtime status;
* `none` qualification effect;
* `not_asserted` external effectiveness claim;
* pending independent review and blocked promotion state.

## Independent review and promotion

A replay cannot authorize its own promotion. Promotion assessment requires
accepted reviews from both `independent_assurance` and `independent_control`.
Reviewers must have distinct identities, and neither reviewer may be the replay
producer. Every review binds the exact receipt identity and digest.

Missing review roles keep promotion blocked. Any rejected review also keeps it
blocked. Even an eligible promotion assessment is only a deterministic policy
observation. The harness does not deploy, qualify, or promote an artifact.

## Example

```python
receipt = run_defender_replay(request)
verify_defender_replay_receipt(receipt)

promotion = assess_replay_promotion(
    receipt,
    (independent_assurance_review, independent_control_review),
)
```

The caller remains responsible for securely storing receipts, collecting real
telemetry, performing independent human review, and deciding whether any later
operational action is authorized.
