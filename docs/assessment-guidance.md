# Deterministic Assessment Guidance

`sunderkey.assessment_guidance` closes the repository contract boundary for
assessment priority and strategy guidance. It converts caller-supplied,
already-governed references into deterministic coverage objectives and
proposal-only scheduler hints.

This capability is repository-only and nonqualifying. It does not authorize,
schedule, route, deploy, discover, contact a target, read credentials, open a
network connection, or execute assessment activity. A guidance card is an
input to later policy, approval, admission, scheduling, and execution layers.
It is not evidence that any product workflow or target interaction occurred.

## Accepted inputs

A request binds every input to one tenant, context, and scope. It accepts:

- assessment goals with immutable acceptance digests;
- ranked focus and exclusion priorities;
- opaque endpoint and role references;
- versioned attack-type selections with risk estimates;
- bounded plain-text custom strategy guidance;
- immutable, nonexecutable payload fixture references;
- attack-surface gap references;
- world-model frontier references;
- exact target-context, service-contract, scope, attack-surface, and
  world-model hashes;
- risk, request, token, parallelism, and impact ceilings; and
- an explicit creation and expiration interval.

Inputs are references and hashes. Raw endpoint locations, payload bytes,
credentials, and secrets are outside this contract.

## Fail-closed validation

The builder rejects:

- unknown, duplicate, noncontiguous, or contradictory priorities;
- a protected endpoint that is focused or lacks an explicit exclusion;
- cross-tenant, cross-context, cross-scope, or out-of-scope records;
- endpoint records bound to a different service contract;
- gap or frontier records from another context;
- attack selections that exceed the risk budget or impact ceiling;
- moving artifact versions such as `latest`, `main`, or partial versions;
- executable or credential-bearing payload fixtures;
- raw secret patterns, command syntax, URLs, and hostile custom instructions;
- expired or inverted validity intervals;
- unknown fields, malformed identifiers, malformed hashes, or noncanonical
  text; and
- any serialized record whose content address does not match its content.

Parsing uses exact field sets for the card and every nested record. The JSON
Schema also sets `additionalProperties` to `false` throughout. Runtime parsing
recomputes both the request digest and the card identity, so valid-looking
field substitution is rejected even when it passes basic type validation.

## Output

The content-addressed guidance card contains:

- ordered coverage objectives for goals, endpoints, roles, attack types,
  attack-surface gaps, and world-model frontiers;
- ordered scheduler hints whose status is always `proposal_only`;
- explicit gap reason codes and nonfatal conflict reason codes;
- blocker codes when payload fixture review is required;
- the exact request, request digest, and expiration; and
- a fixed no-effect declaration for authorization, credential access,
  deployment, discovery, execution, network access, routing, scheduling, and
  target contact.

High-risk attack guidance, any custom strategy, or any payload fixture
reference sets `independent_review_required` to `true`. The flag records a
required downstream control. It does not perform or satisfy that review.

## Deterministic ordering

Explicit focus rank takes precedence. Remaining objectives are ordered by
objective family and opaque subject reference. Exclusions remove subjects from
coverage generation. Every objective and hint receives a contiguous order and
a deterministic opaque reference. Collections are normalized before hashing,
so caller input order does not change the card identity.

## Integration boundary

Call `build_assessment_guidance(request)` after target context, scope, service
contract, attack-surface, and world-model artifacts have been approved by the
appropriate upstream contracts. Persist the returned card as immutable
evidence. A separate admission layer must validate expiration, approvals,
current artifact versions, safety policy, authorization, and infrastructure
health before any hint can influence live scheduling.

Use `parse_assessment_guidance(raw)` when loading a stored card. Do not trust a
card that has not passed strict parsing and content-address verification.
