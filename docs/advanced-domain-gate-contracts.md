# Advanced-domain gate contracts

This increment supplies repository-only contracts for roadmap packages D8.6,
two-deep critical roles, and D8.8, advanced-domain safety. It defines how a
caller can prove that required safety conditions are represented without
granting authority or activating work.

The module is intentionally inert. It performs no routing, activation,
authorization, deployment, network access, target action, or qualification
change. A successful evaluation has status `contract_ready_unverified`. It is
not permission to operate in a live environment.

## Critical-role roster

`CriticalRoleRoster` binds the exact Army registry version and digest, the
exact qualification standard version and digest, and four mandatory role
pairs:

1. domain command;
2. safety;
3. validation;
4. high-value specialty.

Every role has a primary and an alternate. The two candidates must have
different candidate identities, maintainers, and failure domains. Candidate
identities cannot be reused across roles. Each candidate carries current,
content-addressed qualification evidence and a separate qualification
reviewer. A candidate, profile, or maintainer cannot review that candidate's
qualification.

Human candidates cannot carry a model binding. Model and hybrid candidates
must pin a provider, model identifier, and exact model version. When both
members of a role pair are model-backed, they must use different providers.
This captures provider concentration risk in addition to the explicit failure
domain check.

## Advanced domains

`DomainSafetyPolicy` covers six high-risk domain classes:

| Domain | Army v2 commander | Maximum tier |
| --- | --- | --- |
| OT and cyber-physical systems | `AOE-GD-D19-CMD` | `R0` |
| Healthcare | `AOE-GD-D25-CMD` | `R0` |
| Transport | `AOE-GD-D25-CMD` | `R0` |
| Specialized protocols | `AOE-GE-D22-CMD` | `R1` |
| Model infrastructure | `AOE-GD-D20-CMD` | `R1` |
| Other high-risk domains | An explicit Army v2 domain commander | `R0` |

The policy binds one critical-role roster and exact, hashed versions of the
hazard method, simulator or replica proof requirements, monitoring contract,
stop contract, cleanup contract, restoration contract, and evidence custody
contract. The fixed action-tier ceiling cannot be increased by a caller.

## Activation request

`DomainActivationRequest` binds all of the following to one immutable basis
digest:

- requesting profile and Army v2 domain commander;
- domain, environment class, and requested action tier;
- critical-role roster ID and digest;
- safety policy ID and digest;
- signed scope, target-authority record, and deployment profile;
- hazard analysis;
- simulator or replica evidence;
- target authority;
- monitoring, stop, cleanup, restoration, and custody evidence;
- request issuance and expiry.

Every evidence item carries an exact artifact version and digest, producer,
separate reviewer, accepted disposition, scope and policy digests, action
tier, environment class, issuance time, and expiry. Simulator or replica proof
must identify one of those non-live environments even when the proposed
environment is live. All other evidence must match the proposed environment.

Independent Control and Independent Assurance each sign the same activation
basis digest. Their reviewers must be different from each other and from the
requester, domain commander, critical-role candidates, candidate profiles,
and maintainers. The evaluator denies role aliasing and self-review.

## Live-environment requests

A live request also requires `CanaryAdmission`. The admission binds separate
canary evidence to the exact safety policy, scope digest, and action tier. Its
decision maker and independent reviewer must be different from each other,
the critical-role roster, domain commander, requester, Independent Control,
and Independent Assurance. The canary admission must be current at evaluation
time.

This record represents evidence that a separate canary process admitted the
bounded request. It does not perform that process, deploy a canary, or make the
live request executable.

## Fail-closed evaluation

`evaluate_domain_activation` returns `denied` with stable blocker codes when
it detects any of these conditions:

- policy, roster, scope, evidence, review, or canary binding mismatch;
- missing required evidence, including cleanup or restoration proof;
- stale roster, policy, request, qualification, safety, review, or canary
  evidence;
- wrong domain commander;
- action tier above the fixed domain ceiling;
- evidence for the wrong environment;
- missing simulator or replica proof;
- missing separate live canary admission;
- aliased independent reviewers or prohibited self-review.

The compatible state remains `contract_ready_unverified`. Infrastructure is
still required to verify signatures and revocations, establish production
identity, prove runtime isolation, exercise stop and restoration procedures,
observe a controlled canary, and issue any separate operational admission.

## Serialization

All top-level records use canonical ASCII JSON and content-derived IDs and
digests. `parse_contract` recomputes each identity and rejects unknown fields,
hash changes, moving version aliases, malformed timestamps, and effect
escalation. The strict JSON Schema is
`registry/schemas/advanced-domain-gate-contract-v1.schema.json`.
