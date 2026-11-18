# Assessment Strategy Coordinator

## Purpose

The Phase 173 coordinator combines four existing, content-addressed planning
artifacts into one deterministic proposal:

1. An `AssessmentGuidanceCard` supplies explicit goals, gaps, frontiers, risk
   ceilings, impact ceilings, and review requirements.
2. An `AttackCoverageMatrix` supplies coverage status, prerequisites,
   specialist references, negative space, and blocked reasons.
3. An `AssetRiskPortfolio` supplies transparent composite risk and missing
   evidence signals for each asset.
4. An `ImpactDemonstrationPlan` supplies evidence-only impact policy status,
   artifact ceilings, denial reasons, cleanup controls, and review status.

The output is an `AssessmentStrategyPlan`. Every work item remains
`proposal_only`. The plan cannot grant authority or cause operational effects.

## Exact input binding

The caller first captures a `StrategyInputIdentities` record with
`strategy_input_identities`. The coordinator rebuilds and verifies every source
artifact, then compares its content ID and digest with that record. It rejects
changed content, digest substitution, duplicate identities, or a mismatch in
tenant, context, scope reference, or scope digest.

The output embeds the four verified source documents and publishes a compact
lineage record for each one. Strict parsing rebuilds every nested document and
the strategy plan. A changed source, derived field, ranking component, work
item identity, or plan identity fails closed.

## Ranking rules

Ranking uses nonnegative integers only. There is no random input, hidden model
score, clock read, environment read, or unstable tie breaker.

| Signal | Component |
| --- | ---: |
| Asset composite risk | Existing portfolio score in basis points |
| Missing asset evidence | 2,500 per missing evidence category |
| Explicit goal | 8,000 plus deterministic ordering preference |
| Guidance gap | 10,000 plus deterministic ordering preference |
| Guidance frontier | 9,000 plus deterministic ordering preference |
| Coverage gap base | 6,500 |
| Partial, gap, or blocked status | 1,500, 2,500, or 3,000 |
| None or catalog-only evidence | 2,000 |
| Impact evidence policy | 4,000 plus 500 per evidence intent |

Work items sort by descending component sum, then work kind, then subject
reference. Each item publishes its component map and verifies that the sum is
the published priority score.

## Proposal content

Each ordered work item contains:

- its subject and source content identities;
- reason codes and any blocked reasons;
- prerequisite references;
- bound specialist capability references when the coverage matrix supplies
  them;
- risk and impact ceilings from the guidance card;
- an independent review requirement;
- explicit stop conditions for authorization, scope, input identity, and
  target-contact changes.

Unfavorable inputs do not disappear. Missing risk evidence and coverage
blockers receive visible priority components and blocked reasons. A denied or
disabled impact plan produces a blocked evidence proposal. The coordinator
does not reinterpret denial as permission.

## Safety boundary

The module has no transport, target, credential, scheduler, router, or executor
dependency. It does not:

- schedule or route work;
- authorize an action;
- resolve or access credentials;
- execute a command, payload, exploit, or tool;
- contact a target or use a network;
- claim live validation, production readiness, qualification, or competitive
  parity.

The strict canonical ASCII JSON parser rejects duplicate object keys,
noncanonical serialization, unknown fields, unknown enums, moving versions in
nested inputs, secret-like content, hostile instructions, and executable
payload material. The Draft 2020-12 schema provides a separate structural
validation boundary.

## Minimal integration

```python
from sunderkey.assessment_strategy_coordinator import (
    build_assessment_strategy_plan,
    strategy_input_identities,
)

identities = strategy_input_identities(guidance, coverage, risk, impact)
plan = build_assessment_strategy_plan(
    identities=identities,
    guidance=guidance,
    coverage=coverage,
    risk=risk,
    impact=impact,
)
document = plan.document_json
```

Capturing identities and building the plan are separate on purpose. A caller
can present or independently review the exact proposed inputs before
coordination, then fail closed if any source changes before plan construction.
