# Supplied Agent Credential Boundary

This R0 partial component belongs to `AOE-GD-D20-S15`, capability
`army.gd.d20.s15`, vector `AV-GD-D20-S15-01`, work package
`IWP2-AOE-GD-D20-S15`, and wave `IW2-005`. Its commander is
`AOE-GD-D20-CMD`, and its independent validator reference is `AOE-HQ-35`.
It is not a complete candidate, qualified specialist, or live assessment.

The version 1 model is designed to contain only opaque credential reference identifiers,
declared approved agent identifiers, audience and scope labels, status,
expiration epoch seconds, and supplied use records. Operators must not put
tokens, keys, or secrets into identifier fields; this algorithm cannot detect
a secret disguised as an identifier. For each complete use, it compares the agent,
audience, required scopes, status, and invocation time with the declared
credential boundary. A declared revoked, unapproved, out-of-audience,
under-scoped, or expired use becomes a candidate with explicit reasons.
Unknown status, expiration, or context remains unknown.

These are caller declarations. The analyzer does not authenticate the
credential source, inspect a real vault, contact an agent or provider, use
a credential, or establish that an invocation occurred. Time comparisons
use the supplied epoch seconds, not a live clock. A candidate is a
declared contradiction, not observed credential abuse.

`analyze_supplied_agent_credential_boundary` creates an unsigned report
that binds the original model by digest without re-emitting it. Verification
requires a separately retained original model through
`verify_supplied_agent_credential_boundary` or its bounded JSON-byte
variant. The checked synthetic envelope is
`examples/offline-agent-credential-boundary-component.json`.

The result grants no authority, finding, routing, candidate assembly, or
qualification.
