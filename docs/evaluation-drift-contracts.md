# Evaluation Drift Contracts

SUNDERKEY can now represent repeatable offline, shadow, and canary evaluation
comparisons without introducing a model runtime or deployment path. The
contracts pin the control, candidate, distribution, version, cohort, evidence,
policy, and result into content-addressed records.

## Contract boundary

The module is deliberately limited to computation over supplied measurements.
It makes no model calls, duplicates no traffic, opens no network connection,
selects no route, changes no deployment, and grants no authorization. Shadow
mode records comparison results but always has `operational_decision` set to
false. Canary output is a progression plan only and is never deployment
authority.

## Evaluation records

`DistributionBinding` pins a named distribution version, its artifact digest,
and its required strata. `EvaluationCohort` binds sorted per-stratum sample
counts to that distribution and carries explicit collection and expiration
times. `MetricObservation` binds one fixed-point measurement to a cohort,
subject, subject version, source digest, metric, strata, sample count, and
observation time. `EvaluationBaseline` pins a complete control observation set.

The eight mandatory dimensions are safety, correctness, abstention, finding
quality, false-positive rate, false-negative rate, latency, and cost. Values
are integer microunits so comparison is deterministic and does not depend on
platform floating-point behavior.

All cohorts, observations, baselines, assessments, and canary plans verify
their identifiers and SHA-256 digests during construction and deserialization.
Unknown fields fail closed.

## Regression rules

Each metric has a direction, allowed regression, minimum sample count,
optional hard candidate limit, and criticality flag. A result fails when its
direction-adjusted regression is greater than the allowed value. Equality is
accepted, making the threshold edge explicit. A hard candidate limit is also
enforced in the metric's configured direction.

Confidence labels are deterministic evidence-volume bands:

* minimum at the configured sample floor
* moderate at twice the sample floor
* strong at four times the sample floor

These labels describe evidence volume only. They do not claim statistical
significance, causality, or proof.

The assessment stops on stale evidence, a cohort below or above its explicit
sample bounds, missing required strata, missing observation strata,
insufficient per-metric samples, a critical safety regression, or a cost value
over its hard budget limit. All computed metric results remain in the stopped
assessment, including unfavorable outcomes.

## Canary progression

A canary plan contains ascending bounded exposure stages, minimum observation
counts, rollback criteria, and independent review gates. Readiness requires:

* a passing assessment created in `canary_plan` mode
* an approved `independent_control` gate
* an approved `independent_assurance` gate
* distinct reviewer identities
* at least one rollback criterion

Even a ready plan is labeled `ready_for_separate_authorization`. It cannot
authorize or perform progression. A missing or rejected gate, separation
failure, non-passing assessment, wrong mode, or absent rollback criteria keeps
the plan blocked.

## Security properties

Inputs accept printable ASCII identifiers and descriptions, enforce bounded
collections, reject common secret forms, reject stale evidence, and preserve
exact distribution and version bindings. Serialization uses sorted canonical
JSON with no non-finite numeric values. The schema rejects unknown fields and
fixes the no-effects boundary in the serialized assessment.
