# Instrumented range contracts

The instrumented range contract layer defines reproducible synthetic security
range inputs and evaluates supplied readiness evidence. It supports roadmap
item E3.1 without claiming that a live range exists.

## Contract set

`SyntheticApplicationManifest` binds an application definition to exact source,
build, and container image hashes. It also records ground-truth vulnerabilities,
negative controls, seeded data fixtures, opaque seeded-secret and canary
references, network boundaries, resource quotas, telemetry channels, health
probes, and the baseline snapshot.

`RangeScenarioManifest` binds a scenario to one exact application manifest. It
enumerates the expected ground truth, negative controls, telemetry, health
probes, reset procedure, baseline, and restoration checks.

`RangeReadinessObservation` is caller-supplied evidence. It identifies the
observed context, last reset, current snapshot, contamination status, health and
telemetry results, restoration checks, and a durable evidence digest. It is not
a live probe result produced by this module.

`RangeReadinessAssessment` is the deterministic result of comparing the three
inputs at a stated evaluation time. All four top-level records are immutable,
strictly parsed, canonically serialized, and content-addressed.

## Fail-closed readiness

`assess_range_readiness` returns `not_ready` when evidence is stale or from the
future, when application or scenario contexts differ, when ground truth or
negative controls are incomplete, or when definitions do not cover required
telemetry and health probes. It also rejects readiness when reset and baseline
evidence does not match, contamination is reported, any required health probe
fails, telemetry is missing or blind, or restoration checks are missing or
failed.

A `ready` assessment means only that the supplied, content-addressed evidence is
internally consistent under this offline contract. Deployment qualification and
live range acceptance require separately authorized infrastructure evidence and
independent review.

## Explicit non-effects

The module performs no container start, exploit execution, network access,
secret resolution, or state change. It does not inspect a live range and does
not produce a live-readiness claim. Secret and canary values are prohibited;
only opaque provider and version references are accepted.

## Serialization

The schema is published at
`registry/schemas/instrumented-range-contract-v1.schema.json`. Parsers require
exact fields and recompute content addresses, so unknown fields and modified
payloads fail closed.
