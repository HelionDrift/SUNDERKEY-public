# Evaluation Scoring Runtime

Roadmap item WQ-005 is implemented by the deterministic repository-only
scoring runtime in `src/sunderkey/evaluation_scoring_runtime.py`. The runtime
turns caller-supplied scored observations into a content-addressed scorecard
receipt. It does not execute an evaluation or obtain evidence.

## Boundary

The runtime has no authority or external effects. It does not call providers,
models, tools, networks, targets, ranges, or filesystem discovery. It does not
download a corpus, grant qualification, promote a candidate, or perform an
independent review. Every receipt records these effects as `none`.

A score that otherwise passes has the promotion disposition
`independent_review_required`. That review must occur outside this runtime and
must remain separate from candidate ownership, evaluation, and score
calculation.

## Inputs

The caller supplies all data explicitly:

* An immutable evaluation program contract identity and digest.
* A runner result manifest digest.
* The fixed case membership, including all five corpus partitions and repeat
  group indexes.
* The four subject roles: deterministic, generalist, prior release, and
  candidate.
* At least two sorted evaluator identities and a separate scoring controller.
* One contamination attestation for every corpus partition.
* Sorted observations bound to a case, subject, evaluator, evidence manifest,
  result status, budget, and exact metric source values.
* A regression threshold for every scorecard measure.
* A caller-supplied calculation timestamp and immutable scorecard version.

Subjects, evaluators, and the scoring controller must have separate
identities. Observations cannot cross their bound case, partition, subject, or
evaluator. Duplicate case observations are rejected. Duplicate evidence
identities make the evidence invalid.

## Fixed corpus controls

Every corpus partition must meet the configured case minimum. Every repeat
group must have exactly contiguous indexes and at least three runs, matching
the evaluation comparison policy. Repeat groups cannot cross partition
boundaries.

The receipt expects one observation for every fixed case and subject role.
Missing observations, failed observations, abstentions, an evaluator with no
observations, or an unknown contamination state produce an insufficient
evidence result. A contaminated partition produces invalid evidence.

This distinction is intentional:

* `scored_fail` means complete, valid evidence produced a score below a fixed
  threshold.
* `insufficient_evidence` means the runtime cannot calculate a complete score.
* `invalid_evidence` means an integrity, contamination, budget, or consistency
  rule failed.
* `hard_failure` means a critical gate or critical metric threshold failed.

None of these states is converted into a qualification decision.

## Exact metric calculations

The runtime imports the eleven metric definitions from
`evaluation_program_contracts`. It records a digest of those definitions in
the receipt. Caller-supplied metric definitions are not accepted.

The calculations use integer arithmetic only:

* A basis point measure is `numerator * 10000 // denominator`.
* A count measure is the aggregate numerator.
* Milliseconds, micro USD, and milli hops per run use
  `numerator // denominator`.

A denominator below the definition minimum produces an insufficient metric.
The runtime does not substitute a denominator or drop a case. Completed
observations must provide every exact source field. Ratio measures cannot have
a numerator greater than their denominator.

The fixed measures are:

1. Ground truth recall.
2. Validated finding precision.
3. Validator reproduction rate.
4. Attack path depth.
5. Unauthorized target actions.
6. Cleanup completion.
7. Time to first verified finding.
8. Cost per verified finding.
9. Run to run stability.
10. Evidence completeness.
11. Customer remediation acceptance.

Each metric result records the aggregate numerator, aggregate denominator,
minimum denominator, calculated value, sample count, threshold, unit,
direction, outcome, and confidence status. The runtime reports only
`sufficient` or `insufficient` confidence. It does not invent statistical
confidence when the supplied evidence cannot support it.

## Budgets and cost normalization

Each observation includes request, token, tool call, latency, and cost maxima,
plus corresponding usage. Usage beyond any maximum makes the evidence
invalid. Every subject for a case must use the same maximum budget profile,
which enforces the policy requirement for same-case, same-budget comparison.

The supplied evaluation cost must equal the cost in the observation budget.
The subject budget summary records total used cost, total maximum cost, and
normalized cost in basis points:

`used_cost_microusd * 10000 // maximum_cost_microusd`

Cost per verified finding remains a separate fixed scorecard measure.

## Critical failures

A safety failure observation must name one or more known critical gate IDs and
cannot claim ordinary metric values. A non-safety result cannot name a
critical gate. Critical failure gates are sorted and deduplicated.

The scorecard definitions also contain hard thresholds for unauthorized target
actions and cleanup completion. Breaching either threshold creates a hard
stop and records the gates bound by the metric definition. Hard stops are not
averaged into a composite score.

## Baseline comparisons

The candidate is compared separately with deterministic, generalist, and
prior-release baselines for each measure. Weighted composites are not used.

For a higher-is-better measure, directional delta is:

`candidate_value - baseline_value`

For a lower-is-better measure, directional delta is:

`baseline_value - candidate_value`

A negative delta below the configured regression threshold is a regression. A
positive delta is an improvement. A zero delta is no improvement, matching the
fixed tie policy. Invalid evidence, insufficient evidence, and hard stops stay
distinct in every comparison.

## Receipt integrity

The receipt includes all normalized inputs, observations, calculated subject
scores, comparisons, reason codes, definition digests, effects, and policy
dispositions. Its SHA-256 identity is calculated over canonical printable
ASCII JSON plus the contract domain. The receipt parser rebuilds the complete
scorecard and rejects unknown fields, changed calculations, changed inputs,
and identity mismatches.

The reconstructed scorecard must match the supplied canonical JSON, including
integer and boolean types. Import rejects boolean or float substitutes for
integer calculations or schema versions instead of silently normalizing them
to a different receipt. Readdressing an incorrect calculated value does not
make it valid. Ordinary native integer receipts retain their existing identity
and all effects remain `none`.

The schema at
`registry/schemas/evaluation-scorecard-receipt-v1.schema.json` uses JSON Schema
Draft 2020-12 and rejects unknown fields throughout the receipt.
