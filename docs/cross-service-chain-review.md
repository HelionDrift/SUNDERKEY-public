# Offline Cross-Service Chain Review

This C4.9 extension checks caller-supplied metadata for a proposed sequence
of cross-service actions. It does not use a credential, contact a target,
authorize an action, or demonstrate that any transition succeeded. It
complements the [identity path hop plan](identity-path-hop-plan.md), which
maps potential identity evidence but does not review attempted actions.

## Plan And Observation Contract

`build_cross_service_chain_review` accepts a closed chain plan with one tenant,
mission, scope digest, source digest, and a window no longer than 24 hours.
There may be 1 to 16 ordered hops. Every hop names opaque source and target
surface references, domain classifications, a consistent boundary kind,
action tier and digest, policy snapshot, evidence and cleanup requirements,
and an optional opaque credential transition. The path must be connected.
The only credential forms are an opaque `credentialref:sha256:` reference and
a separate binding digest. Raw credentials, URLs, hostnames, and payloads are
outside the contract.

Observed metadata must be an ordered prefix of the plan. Each observation
binds the exact planned hop, scope, action, credential binding, a distinct
admission digest, an actor and attempt reference, a bounded time window,
asserted outcome, evidence and custody digests, and cleanup state. The
review rejects admission reuse, a mismatched hop, an expired attempt, and
continuation after a blocked or unknown outcome. It reports planned
credential-reference reuse without treating reuse as safe, authorized, or
successful. Pending cleanup remains visible even when a hop is blocked.

The report distinguishes `not_started`, `declared_partial`,
`declared_stopped`, and `declared_complete_pending_independent_review`.
Even the last state is only a consistent caller assertion. It is not proof
of reachability or exploitability. `verify_cross_service_chain_review`
reproduces the exact report from the same sources; it does not authenticate
the sources. The closed output schema is
[`cross-service-chain-review-v1.schema.json`](../registry/schemas/cross-service-chain-review-v1.schema.json).

## Remaining Operational Boundary

Authenticated per-hop admission, current target scope, credential brokerage,
qualified runners, trusted evidence custody, stop propagation, cleanup
verification, and independent chain reproduction are separate prerequisites
for a live path claim. An admission digest in this offline report is not an
admission receipt verified by SUNDERKEY. Every reported authority, network,
credential-access, execution, and qualification effect is `none`.
