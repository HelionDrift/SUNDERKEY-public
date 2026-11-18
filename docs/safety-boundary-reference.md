# Safety boundary reference

These detailed safety and authenticated-control notes were moved from the
README at source release 0.285.0. Phase-specific descriptions preserve their
original implementation context. They do not override later signed-runtime,
live-currentness, reviewer-admission, or target-health requirements.

Start with the [current operating boundary](../README.md#operating-boundary).
Use the exact operation's current CLI help and runbook before changing state.
Content integrity alone is never target authority or independent qualification.

## Detailed phase notes

This repository plans, validates, and coordinates authorized security
assessment work. It includes no built-in external network, credential, target,
or tool authority. The HTTP, browser, target-session, target-health,
target-context, and enterprise identity boundaries can use only separately
supplied, exact-bound adapters after their callers satisfy the applicable
scope, admission, resolver, safety, policy, budget, environment, evidence, and
clock controls. Those injected capabilities are not production readiness or
general target authority.

The control plane enforces:

- mission-bound R0-R5 action tiers;
- E0-E4 evidence requirements;
- exact scope-token binding;
- active-role assignment;
- independent authorization;
- executor-bound canonical action hashes;
- single-use authorizations;
- terminal local mission admission control;
- auditable approval revocation;
- independent findings and E4 reproduction;
- append-only typed mission events.

Phase 5 packages those contracts for terminal mission stop only. A signed
scope grant must be accepted before a separately signed assertion can stop a
mission. The assertion derives the profile and binds the exact parsed stop
intent, including the idempotency-key hash. The stop and its authenticated
provenance commit in one SQLite writer transaction.

Lower-level service methods remain trusted in-process primitives. Supplying a
profile ID directly to one of those methods is not authentication. Phase 8
protects generic event append after trust-policy enrollment. Phase 9 protects
approval and denial decisions. Phase 10 protects approval submission. Phase
11 protects approval revocation. Phase 12 protects simulation consumption.
Phase 13 protects mission creation. Phase 14 protects collaboration-plan
activation. Phase 15 protects owner-only work-item lease transitions.
Phase 16 protects same-owner recovery requests and independent Control
decisions. Phase 17 protects terminal work-item cancellation and deterministic
descendant propagation. Phase 18 protects one-time specialist handoff through
paired planned-owner authorization and candidate acceptance. Phase 19 adds a
read-only verified audit projection and no mutation boundary. Phase 20 maps
every specialist to an explicit capability and reports readiness without
qualifying or activating any profile. Phase 21 turns the qualification gap
into explicit evaluation plans without accepting evidence or changing
registry status. Phase 22 evaluates complete synthetic observation sets
against the planned numerical thresholds, but its reports remain unsigned,
advisory, and unable to qualify a candidate or change routing. Phase 23 binds
concrete candidate definitions to content-addressed component manifests and
reports implementation gaps without claiming deployment or competence. Phase
24 gives every specialist an exact provider-neutral build blueprint while
leaving those implementation gaps unchanged.

The Phase 6 CollaborationPlan is scope-referenced but unsigned. It organizes
the assigned specialists and commanders without dispatching a model,
executing a task, inferring a capability, issuing a credential, recording
mutable status, or authorizing an action. Its deterministic hashes bind
content for comparison; they do not establish provenance or replace a signed
scope grant and case-specific authorization.

The plan carries the common mission objective and a registry-defined role
mission for every work item. Every assembled-cell profile receives at least
one owner or support assignment. Consumers must treat `(plan_id,
work_item_id)` as the task identity and validate the plan against the exact
bound registry and mission before using it.

Phase 7 revocation is a scope-authority lifecycle action, not a
`PrincipalOperation`. A root-signed policy must enroll a distinct
`scope_grant_revocation` key before SUNDERKEY can accept an externally signed
revocation. Acceptance is prospective, store-local, and does not stop the
mission automatically. Migrated version 3 revocation values remain explicitly
unsigned historical provenance.

Phase 8 requires the event actor to come from the signed assertion. The
assertion binds the exact ordered batch hash and starting mission revision.
EVENT_APPEND v1 has no local idempotency argument. Exact retry uses the
assertion identity, and a different assertion cannot claim the same signed
request or any existing event ID.

Phase 9 requires approve and deny actors to come from signed assertions. Each
intent binds one approval, the expected version, all decision fields, the
derived Control profile, and the hash of the local idempotency key. The
decision event, approval transition, protected effect, assertion use, and
principal-ledger update commit together.

Phase 10 requires the approval proposer to come from a signed assertion. The
intent binds the mission, proposal, executor, review expiry, derived proposer,
and hash of the local idempotency key. The pending approval, protected effect,
assertion use, and principal-ledger update commit together.

Phase 11 requires the approval-revocation actor to come from a signed
assertion. The intent binds the approval, expected version, reason code,
reason, risk, decision owner, derived Control profile, and hash of the local
idempotency key. The blocker event, revocation record, approval transition,
protected effect, assertion use, and principal-ledger update commit together.
Approval revocation has no expired-scope grace.

Phase 12 requires the simulation executor to come from a signed assertion.
The intent binds the approval, derived executor, and hash of the local
idempotency key. The fixed plan-only receipt, approval consumption, protected
effect, assertion use, and principal-ledger update commit together without
appending a mission event or changing the mission revision. New simulation
requests have no expired-scope grace.

Phase 13 requires the prospective mission, signed scope grant, and signed
principal assertion in one creation request. The intent binds the mission ID,
deterministic context hash, and assertion-derived creator. Mission state,
scope acceptance, protected effect, assertion use, principal ledger, and
creation provenance commit together. Mission creation has no expired-scope
grace.

Phase 14 requires a deterministic plan that exactly matches the stored
mission and reviewed registry. The intent binds the mission, plan ID, plan
content digest, and assertion-derived readiness owner. Plan activation,
protected effect, assertion use, and principal-ledger advancement commit
together. Activation does not claim work or authorize execution.

SUNDERKEY ships no trust root, private key, signing command, operational
credential issuer, or key generator. Trust-bootstrap commands enroll public
trust material only. Root pinning does not activate authenticated mode. The
first verified policy does, and that transition cannot be reversed for the
store. After activation, direct trusted-local `mission-stop` is rejected and
`mission-stop-authenticated` is required. Direct generic event append is also
rejected and `event-append-authenticated` is required. Direct approval and
denial decisions are rejected and their authenticated commands are required.
Direct approval submission is rejected and
`approval-submit-authenticated` is required. Direct approval revocation is
rejected and `approval-revoke-authenticated` is required. Direct simulation
consumption and direct exact retry are rejected and
`simulate-authenticated` is required. Direct mission creation and direct exact
retry are rejected after policy enrollment and
`mission-create-authenticated` is required.
Collaboration-plan activation is available only through
`collaboration-activate-authenticated`; there is no trusted-local activation
path.
