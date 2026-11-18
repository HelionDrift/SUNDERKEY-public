# Supplied Service-Secret Lifecycle Projection

This R0 offline component adds partial algorithm coverage for specialist
`AOE-GA-D03-S11`, capability `army.ga.d03.s11`, vector
`AV-GA-D03-S11-01`, work package `IWP2-AOE-GA-D03-S11`, and wave `IW2-012`.
The domain commander is `AOE-GA-D03-CMD`, and independent validation is
assigned to `AOE-HQ-19`. It is not a completed candidate or qualified agent.

The version 1 model accepts only synthetic service-account and secret
references, bounded logical ticks, declared maximum rotation ages, issuance,
expiration, revocation, and reported outcomes. It has no field for a secret
value, hash, token, endpoint, or executable command. All records are caller
declarations.

The projector evaluates negative lifecycle invariants only. A reported use
before issuance, at or after declared revocation or expiration, or beyond the
declared rotation age may produce a candidate declared mismatch. A secret
that has no negative invariant remains unknown. Incomplete policy or ordering
and missing secret metadata also remain unknown. The projector never infers
that a secret is valid, that a request was allowed, or that a service account
has effective access.

`analyze_supplied_service_secret_lifecycle` emits an unsigned
content-addressed report. The verifier replays a separately retained original
model through `verify_supplied_service_secret_lifecycle` or its bounded
JSON-byte variant. The embedded source cannot authenticate itself. The
synthetic dispatcher input is
[`offline-service-secret-lifecycle-component.json`](../examples/offline-service-secret-lifecycle-component.json).

No key material is processed. No provider request, credential use, target
interaction, finding publication, qualification, or authority change occurs.
A candidate mismatch is not a verified credential leak or vulnerability.
