# Deterministic Asset Risk Scoring

The asset risk scoring module closes the basic open-finding severity-weighted
risk score boundary and adds an evidence-aware SUNDERKEY score. It accepts only
caller-supplied, content-addressed records and publishes one scorecard for each
asset plus a deterministic portfolio ranking.

This is a repository-only calculation boundary. It does not discover assets,
query a target, access a network, use credentials, call a provider, deploy a
service, predict an outcome, authorize an action, perform remediation, or
observe live target state.

## Bound inputs

Every asset has a content-addressed criticality and exposure binding. A binding
contains tenant, context, scope, asset identity, asset digest, criticality,
exposure, evidence coverage, uncertainty, evidence digest, and observation
time.

The optional evidence sets are:

* Open finding records with severity, confidence, validation state,
  remediation state, exception state, evidence coverage, and freshness.
* Attack path evidence with confirmed, not-observed, or unknown reachability,
  path depth, evidence coverage, uncertainty, and freshness.
* Defender detection coverage with detection coverage, evidence coverage,
  uncertainty, and freshness.

Every supplied record must match the asset tenant, context, scope, reference,
and digest. A cross-bound record is rejected. Duplicate asset identities,
finding references, finding digests, record identities, and evidence bindings
are rejected. A finding marked as merged away cannot be scored. These rules
prevent a stale alias, duplicate, or deduplicated record from changing a score.

The caller also supplies a content-addressed policy with an exact version,
maximum evidence age, and minimum evidence coverage. The calculation timestamp
is caller supplied, so the result does not depend on a local clock.

## Simple severity-weighted baseline

The baseline intentionally models a simple open-finding score. Each open
finding contributes a fixed severity weight:

| Severity | Contribution in basis points |
| --- | ---: |
| Info | 250 |
| Low | 1,000 |
| Medium | 3,000 |
| High | 6,000 |
| Critical | 10,000 |

The exact formula is:

```text
baseline_score_bps = min(10000, sum(severity_contribution_bps))
```

Confidence, validation, attack paths, asset importance, defender coverage,
remediation labels, and exceptions do not alter this baseline. They are handled
separately by the composite score.

## Evidence-aware SUNDERKEY composite

All composite calculations use integer arithmetic. A division that calculates
an uncertainty bonus rounds up. All final scores are bounded from 0 to 10,000
basis points.

### Finding contribution

The severity components are 500 for info, 2,000 for low, 4,500 for medium,
7,500 for high, and 10,000 for critical.

Validation adds 0 for candidate, 500 for verified, and 1,000 for reproduced.
An invalid record adds no validation bonus, causes the asset evidence state to
be invalid, and triggers the maximum fail-closed score.

Confidence uncertainty adds:

```text
ceil((10000 - confidence_bps) * 2000 / 10000)
```

Lower confidence therefore never lowers a finding contribution.

Remediation state adds 750 for open and unaddressed, 500 for planned, 250 for
in progress, and 0 for reported remediated. Reported remediated is only a
caller-supplied label. The finding remains in both scores and a reason code
records that the report has not been verified by this module.

Exception state adds 0 for none, 500 for temporary, and 750 for approved. An
exception never removes or discounts a finding.

The exact per-finding formula is:

```text
finding_contribution_bps = min(
    10000,
    severity_component_bps
    + validation_bonus_bps
    + confidence_uncertainty_bonus_bps
    + remediation_bonus_bps
    + exception_bonus_bps
)
```

Multiple findings are aggregated without averaging unfavorable findings away:

```text
finding_aggregate_bps = min(
    10000,
    max(finding_contribution_bps)
    + min(2500, (open_finding_count - 1) * 250)
)
```

### Asset floor

Criticality and exposure establish an asset context floor:

```text
asset_context_floor_bps =
    (criticality_bps * 3 + exposure_bps * 2) // 5
```

The score cannot fall below the largest core signal:

```text
inherent_floor_bps = max(
    baseline_score_bps,
    finding_aggregate_bps,
    asset_context_floor_bps
)
```

### Attack path and uncertainty

A confirmed attack path adds:

```text
max(500, 2500 - min(depth, 20) * 100)
```

Unknown reachability adds 1,500. A fully supported not-observed result adds 0.
A missing attack path binding adds 1,500 plus a 2,000 uncertainty bonus and
makes the evidence insufficient.

For a supplied attack path, uncertainty adds:

```text
ceil((10000 - evidence_coverage_bps) * 1000 / 10000)
+ ceil(uncertainty_bps * 1000 / 10000)
```

Asset uncertainty adds:

```text
ceil(asset_uncertainty_bps * 1000 / 10000)
```

### Defender coverage

Defender evidence uncertainty uses the same coverage and uncertainty formula
as attack path evidence. A missing defender binding adds a 2,000 uncertainty
bonus, applies no reduction, and makes the evidence insufficient.

Verified detection coverage can apply a bounded and visible reduction:

```text
defender_detection_reduction_bps =
    detection_coverage_bps * 2000 // 10000
```

The reduction cannot lower the result below the inherent floor:

```text
pre_control_score_bps = min(
    10000,
    inherent_floor_bps
    + attack_path_bonus_bps
    + attack_path_uncertainty_bonus_bps
    + asset_uncertainty_bonus_bps
    + defender_uncertainty_bonus_bps
)

calculated_score_bps = max(
    inherent_floor_bps,
    pre_control_score_bps - defender_detection_reduction_bps
)
```

The scorecard publishes every contribution and intermediate value. A control
never changes risk without an explicit breakdown entry.

## Evidence states and fail-closed score

Each scorecard publishes one evidence state:

* `complete` means required evidence exists, meets minimum coverage, is fresh,
  and contains no invalid finding record.
* `stale` means at least one supplied record exceeds the policy age.
* `insufficient` means findings, attack path evidence, or defender evidence is
  missing, or minimum evidence coverage is not met.
* `invalid` means a supplied finding is explicitly invalid.

Malformed values, future timestamps, cross-bound data, duplicates, merged-away
findings, and changed content addresses are rejected instead of scored.

For stale, insufficient, or invalid evidence:

```text
published_composite_score_bps = 10000
```

The independently calculated score remains visible as
`calculated_score_bps`, while `fail_closed_floor_applied` records why the
published score is higher. Missing or uncertain evidence therefore cannot
silently make an asset appear safer.

Confidence is the minimum supplied finding confidence. Evidence coverage is
the minimum coverage across the asset binding, findings, attack path, and
defender binding. Missing evidence contributes zero coverage. The scorecard
also publishes maximum evidence age and sorted reason codes.

## Ranking

Portfolio ranking is deterministic. Assets are ordered by:

1. Published composite score, highest first.
2. Evidence state priority: invalid, stale, insufficient, then complete.
3. Baseline score, highest first.
4. Asset reference, ascending.

Ranks are sequential. Input array order does not change scores, ranks, or
content addresses.

## Integrity and non-claims

Every input binding, per-asset scorecard, policy, and portfolio has a canonical
SHA-256 content address. Parsing a portfolio reconstructs all inputs, formulas,
scores, reason codes, ranks, and identities. Any changed field or derived value
is rejected.

The JSON Schema Draft 2020-12 contract rejects unknown fields and bounds all
arrays and numeric inputs. The module never treats a score as a prediction,
live target observation, remediation result, or authorization decision. Every
portfolio records its external effects and claims as none.
