# Offline API Session Sequence Review

`sunderkey.api_session_sequence_review` covers the repository-only session
sequence portion of V9.5. It consumes an exact, replay-verified sanitized API
traffic inventory, its original observations, and separately supplied event-to-
session sequence claims. It performs no collection, network request, target
interaction, authentication, or release admission.

## Source Contract

Each claim binds an existing `event_id` and `observation_sha256` to a
`sessionref:uuidv4:` label and a zero-based, contiguous position within that
label. Supply randomly generated labels, never raw cookies, tokens, account
identifiers, session IDs, or hashes derived from them. The structural check
does not prove that a label was generated safely. Collection and redaction
must happen before this component receives the claims. A separate
`redaction_review_sha256` records which external review is claimed, but this
module does not authenticate that review.

Claims must be unique by event and session position. The event must be present
in the exact inventory source set, and the observation digest must match.
Events from different sessions cannot create edges. Positions must be
contiguous from zero, and their observation timestamps cannot move backward.
When adjacent events have the same whole-second timestamp, the report flags
their temporal order as uncertain even though the caller supplied positions.
Unbound observations remain explicit in the coverage count.

## Review Output

The report is content-addressed and records ordered observation digests and
adjacent edges per declared session. It counts changes in caller-supplied role
labels and origins, not authentication events or lateral movement. An origin
change is only a review candidate. It does not prove reachability or identity
continuity. The source verifier rebuilds the exact report from the inventory,
observations, claims, and optional service contract bundle. The output schema
is `registry/schemas/api-session-sequence-review-v1.schema.json`.

Session linkage and redaction assurance remain unverified. The output requires
independent review and has no authority, release-gate, or qualification
effect. Live V9.5 still requires approved telemetry, collector and redaction
assurance, authenticated session linkage, authorized validation runners,
release policy integration, and coverage evidence.
