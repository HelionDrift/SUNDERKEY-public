# Attack-surface drift detection

`sunderkey.surface_drift_detection` provides deterministic contracts for
continuous attack-surface comparison and assessment revalidation. It consumes
observations that another trusted boundary has already admitted. It does not
discover targets, resolve DNS, query cloud services, access a network, start a
scheduler, deliver a notification, execute a rescan, or grant authority.

## Observation model

An immutable `SurfaceObservation` represents one of seven surface kinds:

* asset
* endpoint
* schema
* identity
* trust edge
* control
* deployment

Each observation carries a stable surface ID, a digest of the observed content,
a digest of the retained provenance artifact, observation and freshness times,
an assessment scope digest, a risk score, and bindings to technique, profile,
and commander IDs. The evidence state is one of `verified`, `negative`,
`hypothesis`, or `abstained`. These states are retained as evidence meaning and
are never silently promoted to verified.

Freshness is evaluated at a caller-supplied UTC instant. The module does not
read the wall clock. A stale observation remains in the snapshot and produces a
stale-provenance revalidation trigger when it participates in drift.

## Immutable snapshots and lineage

`build_surface_snapshot` canonicalizes admitted observations by surface ID and
builds a content-addressed snapshot. The digest covers all observations,
protection and exclusion lists, limits, scope, sequence, parent digest, capture
time, and the no-effect declaration. Loading a serialized snapshot recomputes
its identity and rejects unknown fields, changed content, and noncanonical
arrays.

A root has sequence zero and no parent. Every successor must:

* bind to the same scope digest
* point to the exact parent snapshot digest
* increment the sequence by one
* advance the capture time
* retain every inherited protected endpoint
* retain every inherited exclusion
* retain the lineage resource limits

These rules reject rollback, skipped baselines, scope substitution, and silent
removal of safety controls. Changing a protection or exclusion policy requires a
separate governed design. This planning contract only supports monotonic
additions.

## Deterministic drift

`assess_surface_drift` compares a baseline only with its direct descendant.
Surface IDs are classified in canonical order as added, removed, or changed.
Meaningful content, evidence, time, risk, technique, profile, and commander
changes are named explicitly in `changed_fields`.

Removed surfaces preserve their full prior observation and use
`uncertain_absence`. Absence from a later observation set is not treated as
proof that an asset or endpoint ceased to exist. Changed or added observations
retain their verified, negative, hypothesis, or abstained meaning. Expired
provenance is labeled `stale_provenance`.

Each change receives a deterministic risk score derived from change type,
surface kind, observation risk, and evidence certainty. A corresponding trigger
contains the union of the prior and current technique, profile, and commander
bindings. Excluded surfaces cannot create notification or rescan plans.
Protected endpoints can create a notification plan, but never a rescan plan.

## Bounded comparison

`DriftLimits` bounds observations, changes, triggers, and plan records. A result
that exceeds a limit fails closed rather than truncating the evidence set. Hard
ceilings prevent a caller from disabling these controls with unusually large
configured values.

## Notification and rescan plans

`plan_revalidation` creates content-addressed records for two action types:
notification and rescan. The records are descriptive only. A `planned`
disposition means a later authorized service may consider the request. It does
not mean the action happened or was authorized.

Prior records provide two replay controls:

* An identical action and trigger dedupe key produces `deduplicated`.
* Another action of the same type for the same surface inside the configured
  cooldown produces `cooldown_suppressed`.

Protected or excluded actions produce `blocked`. Future-dated prior records are
rejected. All results retain the technique, profile, and commander bindings so a
later authority boundary does not need to infer ownership from free text.

## Offline example

```python
from dataclasses import replace

from sunderkey.surface_drift_detection import (
    SurfaceObservation,
    assess_surface_drift,
    build_surface_snapshot,
    plan_revalidation,
)

scope = "sha256:" + "1" * 64
baseline_observation = SurfaceObservation(
    surface_id="endpoint:billing-api",
    surface_kind="endpoint",
    content_sha256="sha256:" + "a" * 64,
    provenance_sha256="sha256:" + "b" * 64,
    observed_at="2026-09-20T10:00:00Z",
    freshness_expires_at="2026-09-21T10:00:00Z",
    observation_state="verified",
    scope_binding_sha256=scope,
    technique_ids=("technique:http",),
    profile_ids=("profile:web",),
    commander_ids=("commander:application",),
    risk_score=60,
)

baseline = build_surface_snapshot(
    (baseline_observation,),
    captured_at="2026-09-20T10:30:00Z",
    scope_binding_sha256=scope,
    protected_endpoint_ids=("endpoint:billing-api",),
)

current_observation = replace(
    baseline_observation,
    content_sha256="sha256:" + "c" * 64,
)
current = build_surface_snapshot(
    (current_observation,),
    captured_at="2026-09-20T11:30:00Z",
    scope_binding_sha256=scope,
    parent=baseline,
    protected_endpoint_ids=("endpoint:billing-api",),
)
assessment = assess_surface_drift(
    baseline,
    current,
    assessed_at="2026-09-20T12:00:00Z",
)
plans = plan_revalidation(
    assessment,
    planned_at="2026-09-20T12:01:00Z",
)
```

The protected endpoint produces a planned notification record and a blocked
rescan record. No notification is sent and no target interaction occurs.

## Serialization

`canonical_json` uses sorted object keys, compact separators, UTF-8 safe text,
and rejects non-finite numbers. The closed assessment schema is
`registry/schemas/surface-drift-assessment-v1.schema.json`. Snapshot,
assessment, trigger, record, and plan identities are derived from canonical
content.

Every snapshot, assessment, and plan set declares the following effects as
`none`: authority, cloud, discovery, DNS, execution, network, notification, and
scheduler.
