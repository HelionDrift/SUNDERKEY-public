# Operator Console Projection

The operator console projection contract provides one content-addressed view of
an assessment for product and operational interfaces. It closes the repository
contract portion of capability package P5.3 without claiming that a browser,
server, database, identity provider, or live worker environment exists.

The projection combines:

- mission state and version
- signed scope, schedule, and status digests
- coverage progress
- request, cost, token, tool, worker-time, and storage budgets
- worker state and heartbeat summaries
- pending approvals
- target and worker health
- graph changes and evidence conflicts
- blockers and ownership
- finding, evidence, and report references
- emergency-stop state
- role-specific control hints

## Role-specific views

The builder supports assessment operator, independent control, independent
assurance, evidence custodian, executive observer, and incident responder
views. Each view removes sections that its role does not need. Executive views
contain aggregate coverage, budgets, and health only. Evidence custodians do
not receive worker, approval, or blocker details. Independent assurance is
read-only and receives no control intents.

These transformations are data minimization, not authorization. The caller is
responsible for authenticating the principal and proving that the requested
view role is valid.

## Control boundary

Displayed controls are only hints about which request types make sense in the
current state. A control creates an immutable operator intent request with:

- the expected assessment version
- the authenticated principal identifier supplied by the caller
- an idempotency key
- a timestamp and rationale
- `authorization_status` fixed to `external_required`
- `effect` fixed to `none`

The intent must enter the authenticated API, scope, approval, admission,
custody, and execution path before anything can change. The console contract
cannot pause, resume, cancel, stop, schedule, route, or execute work.

## Integrity and safety properties

- Projections and intents use deterministic JSON and SHA-256 identities.
- Derived coverage percentages and budget remainders are rechecked on parse.
- Duplicate workers, approvals, blockers, graph changes, and references fail
  closed.
- A recorded emergency stop cannot coexist with a ready or running mission.
- Secret-like text is rejected from blocker details and operator rationale.
- Parsers reject unknown fields, noncanonical JSON, identity tampering, and
  unsupported enum values.

## Infrastructure still required

Production completion of P5.3 still requires a deployed API, authenticated
role mapping, durable event and projection stores, streaming updates, an
accessible user interface, operational telemetry, and integration tests
against real workers and target health sources. This contract supplies the
stable boundary those components can consume.
