# Deterministic Multi-Model Routing

## Purpose

SUNDERKEY can plan which exact provider and model version is suitable for a
bounded assessment task without contacting a provider. The planner consumes
version-pinned capability declarations, task requirements, an external
authority binding, and an immutable budget snapshot. Its output is a
content-addressed route decision that can be reviewed before any separate
execution system uses it.

This capability is infrastructure-independent. It does not contain provider
clients, make model calls, perform network requests, look up pricing, read
secret values, spend a budget, reserve funds, change qualification, or grant
authority.

## Records

`ModelCapabilityDeclaration` pins all behavior used by the policy:

- provider ID and exact provider API version
- model ID and exact model version
- pricing revision and integer micro-USD token rates supplied by a registry
- supported modalities and context and output capacities
- permitted data classifications, hosting mode, and region
- retention and training-use behavior
- tool policy, safety profile references, and qualification references
- measured latency and availability claims
- quality tier and current declared availability

Moving aliases such as `latest`, `stable`, and `default` are rejected. The
router never performs a pricing lookup. Updating a declaration produces a new
content address and therefore requires a new decision.

`TaskRoutingRequirements` binds policy to one tenant, assessment, task, and
requester. It states modality, input, output, and request cost ceilings, data classification,
allowed hosting and regions, retention, training, tools, safety and
qualification requirements, latency, availability, and minimum quality.

`RoutingAuthorityBinding` is an external grant. It identifies the independent
authorizer, requester, tenant, assessment, task, validity interval, and exact
capability content addresses that may be considered. The requester cannot be
the authorizer. Routing cannot create or expand the grant.

`BudgetEnvelope` is an immutable snapshot with per-request and aggregate token
and cost limits plus already reserved aggregate amounts. The cost unit is an
integer micro-USD. Integer arithmetic prevents platform-dependent rounding.

`RoutingDecision` records every candidate evaluation, the selected pinned
route when one exists, an ordered fallback plan, blockers, and a proposed
budget reservation. Its JSON representation is canonical and its identifier
is derived from its content.

## Deny-by-default eligibility

A candidate is ineligible when any required predicate is not proven. The
planner checks all of the following:

1. The declaration is currently marked available.
2. The external authority binding grants that exact declaration digest.
3. Modalities and context and output capacities satisfy the task.
4. Data classification, hosting, region, retention, and training constraints
   are satisfied.
5. Tool policy is an exact match.
6. Required safety and qualification references are present.
7. Latency, availability, and quality floors are satisfied.
8. Per-request and aggregate token and cost budgets have sufficient capacity.

When no candidate satisfies every predicate, the result is `abstained` with a
sorted union of explicit blocker codes. There is no default provider and no
best-effort policy relaxation.

## Ranking and fallback

Eligible candidates receive an integer score under
`cost_latency_availability_v1`. The score orders estimated cost first, then
latency, availability penalty, and quality penalty. Equal scores use provider
ID, model ID, exact model version, and capability digest as stable tie breakers.
Input order cannot change the decision.

The first route is the selected plan. Remaining eligible routes form an
explicit ordered fallback plan. Every fallback contains exact provider API,
model, model version, pricing revision, and capability digest values. The
decision always sets `substitution_requires_new_decision` to true. A runtime
cannot silently replace the selected model with a fallback, a moving alias, or
a lower quality model.

## Budget boundary

For a selected route, the planner creates a `BudgetReservation` with state
`proposed` and `planning_only` set to true. It records request tokens,
estimated cost, and projected aggregate totals. It does not mutate the budget
snapshot or claim that a financial reservation exists. A later budget custody
component must independently authorize and commit any real reservation.

## Serialization and verification

The decision schema is
`registry/schemas/model-routing-decision-v1.schema.json`. It disallows unknown
properties and constrains selected and abstained shapes. Deserialization
recomputes nested reservation and decision content addresses, rejects altered
effects, and rejects unknown fields.

The recorded effects are intentionally narrow:

- budget reservation: planning only
- authority, budget spend, credential values, execution, model calls, network,
  pricing lookup, provider clients, provider state, qualification, requests,
  secrets, and tools: none

## Integration boundary

A future execution service may consume an accepted route decision only after
it independently verifies freshness, authority, qualification, budget custody,
and exact provider and model version availability. Any fallback, declaration
change, expired grant, new pricing revision, or changed task requirement needs
a new routing decision. This module intentionally provides no execution
adapter or credential field.
