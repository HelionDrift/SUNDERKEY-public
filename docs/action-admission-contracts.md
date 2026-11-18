# Atomic action-admission contracts

`sunderkey.action_admission_contracts` defines the repository-only X1.8
decision boundary. It combines every prerequisite for one requested action in
one immutable, content-addressed request and evaluates those prerequisites in
one deterministic, fail-closed operation.

## Atomic binding

An `ActionAdmissionRequest` binds all of the following without wildcard or
implicit context:

- tenant, mission, scope, exact policy version, and policy content address
- worker identity, profile, session, fence token, and leader epoch
- independent approval, maximum action tier, exact target, and exact action
- credential lease, including worker, session, scope, and action restrictions
- fresh worker health evidence
- request, token, and monetary budgets including the cost of the proposed action
- target identity, authority, environment, and content address
- requested action, parameters, tool version, and idempotency key
- all required evidence obligations with exact context and freshness windows
- independent stop monitoring, stop deadline, and impact ceiling
- mandatory restoration ownership and independent completion verification
- the exact hashes of every relevant record

The required evidence set is closed: scope authority, target authority, safety
review, observability, stop readiness, restoration readiness, and custody. A
missing, duplicated, stale, or cross-context item denies admission.

## Fail-closed decision

`evaluate_action_admission` evaluates all prerequisites and returns one
`ActionAdmissionDecision`. It never returns a partial admission. Any context
mismatch, stale prerequisite, exhausted budget, tier overrun, unhealthy worker,
revoked lease, missing evidence, stop-monitor conflict, or restoration mismatch
produces `denied` with canonically ordered reason codes.

The only successful status is `admitted_contract_only`. That label is
deliberate. The result is evidence that the supplied records were internally
consistent at one timestamp. It is not authorization and does not perform or
enable an action.

## Serialization and effects

Requests and decisions use canonical ASCII JSON and SHA-256 content addresses.
Deserialization rejects unknown fields, noncanonical JSON, altered identifiers,
altered digests, invalid vocabularies, and effect escalation. Every record
declares these effects as `none`:

- authorization
- credential use
- dispatch
- network
- restoration
- stop
- target action

Parsers also require the complete reconstructed canonical JSON to match the
supplied document. Equal-valued native JSON types cannot be normalized under an
old identifier or digest. The [integrity regression guide](offline-contract-api-integrity.md)
includes genuine durable admission reconstruction and unchanged identity controls.

The module has no network, credential, orchestration, target, or restoration
client. Live enforcement requires a separately reviewed runtime adapter and
deployment evidence that are outside this contract.

## Verification scope

Focused tests cover the admitted boundary, each denial family, exact budget and
tier boundaries, tampering, cross-tenant and cross-session attempts, stale
evidence, missing prerequisites, canonical round trips, strict JSON Schema,
immutability, marker scans, Unicode dash scans, and the no-effects declaration.
