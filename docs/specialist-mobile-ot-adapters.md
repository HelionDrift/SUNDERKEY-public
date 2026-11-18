# Mobile, Desktop, Wireless, Embedded, and OT Specialist Boundaries

`sunderkey.specialist_mobile_ot_adapters` defines repository-only contracts for five specialist assessment domains:

- mobile applications and platforms
- desktop clients and their local trust boundaries
- wireless configurations, identities, and retained spectrum evidence
- embedded and IoT firmware, interfaces, and device lifecycle boundaries
- OT and ICS protocols, control boundaries, and safety interlocks

The module declares capabilities and produces deterministic requests and receipts. It cannot interact with a target by itself. It has no exploit payload, radio transmitter, device command implementation, process runner, network client, or autonomous execution loop. Only a caller-supplied adapter can attempt an action after every repository boundary check succeeds.

## Action tiers

| Action class | Required tier | Boundary |
|---|---:|---|
| `passive` | R0 | Analyze caller-supplied evidence without a target change |
| `authenticated_read` | R1 | Perform an approved read through an injected adapter |
| `validation` | R2 | Validate one explicitly approved condition without a target change |
| `controlled_change` | R3 | Perform a bounded change with a restoration plan |
| `disruptive` | R3 | Run only in a declared simulation or lab with restoration controls |

The request must state the exact tier for its action class. Tier escalation and tier downgrades both fail before adapter invocation.

## Environment and critical-system controls

Every context declares one environment: `simulation`, `lab`, `staging`, or `production`. Disruptive actions are admitted only in simulation or lab. This rule prohibits disruptive wireless and OT or ICS operations in production and staging. The repository does not contain radio or industrial-control implementations, so this admission result cannot cause such an operation on its own.

Every context also classifies system criticality. Business-critical, safety-critical, and critical-infrastructure contexts require two approval records with distinct actor references. The constructor rejects an absent independent approval or the same actor in both roles.

## Exact bindings

Every request is content-addressed and binds all of the following:

- tenant and mission
- environment and system criticality
- signed scope reference and digest
- target reference and digest
- protocol profile reference and digest
- device identity reference and digest
- session reference and digest
- evidence plan reference and digest
- restoration plan reference and digest
- primary approval, independent approval, and distinct actor references
- operation, byte, change, and duration budgets
- action intent digest and idempotency digest
- activation and expiry times

Dispatch compares the complete request context with the caller's separately supplied expected context. Any cross-context request fails before the injected adapter is called. The adapter observation must echo the exact request, context, target, protocol, device, and session digests.

## Replay, tamper, and budget behavior

Canonical JSON and content-derived identifiers cover declarations, budgets, contexts, requests, and receipts. Parsing rejects unknown fields, changed digests, malformed references, secret-like material, and boundary-effect escalation. Dispatch rejects requests that are stale, not yet active, already seen, or reuse an idempotency digest.

Request estimates and adapter observations must stay within all four budget dimensions. An observation cannot report changes for a passive, authenticated-read, or validation action. There is no retry in this module.

## Restoration behavior

Controlled-change and disruptive requests require a nonempty restoration plan. If an adapter reports an actual change without completed restoration evidence, the receipt is `halted_restoration_required`, never `completed`. The receipt preserves the result for operator response but does not represent restored state.

## Qualification status

Every record has `qualification_effect` set to `none`. This increment is repository-only and nonqualified. Live use requires separately approved adapters, signed authorization, credential custody, hardware and radio controls where applicable, enforced routing, durable replay state, live budget enforcement, evidence custody, restoration workers, safety review, operator interfaces, and independent qualification.
