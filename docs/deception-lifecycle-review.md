# Offline Deception Lifecycle Review

This V9.8 increment reviews caller-supplied metadata for one synthetic decoy or
tripwire plan. It accepts only opaque asset and owner references, SHA-256
digests, whole-second UTC times, and declared lifecycle events. It never
accepts a token secret, deploys a decoy, delivers an alert, contacts a target,
or removes a deployed object. A complete inert example is
[`deception-lifecycle-review-v1.json`](../examples/deception-lifecycle-review-v1.json).

## Plan and Lifecycle Bounds

The plan must declare one nonprivileged unique marker class, a token digest,
scope and owner-approval digests, and digests for both a removal procedure and
a removal test. The declared lifetime is at most 30 days. These hashes bind
caller assertions only. This module does not inspect or verify owner approval,
token privilege, marker uniqueness, or a tested removal path.

Up to 256 events may declare placement, alerts, revocation, and cleanup. Their
timestamps must be strictly increasing after plan creation and no later than
the selected review time. Every event binds the same token digest. Alerts need
an opaque alert reference and follow a placement. Alert references must be
unique within a reviewed sequence.
Revocation and cleanup follow a placement; no duplicate placement, revocation,
or cleanup is accepted. Placement at or after expiry is rejected. Declared
alerts after expiry remain visible as late-alert counts. Alerts after a
declared revocation or cleanup remain visible as separate anomaly counts. A
post-cleanup alert disputes the cleanup claim and leaves cleanup due. A placed
plan viewed at or after expiry, or a revoked plan without cleanup, is also
reported as cleanup due. Cleanup is a declared receipt,
not proof that a resource was removed. Rotation is not activated by this
version; it needs a separate reviewed plan, marker, removal path, and
production-controlled transition.

`build_deception_lifecycle_review` produces a content-addressed report under
[`deception-lifecycle-review-v1.schema.json`](../registry/schemas/deception-lifecycle-review-v1.schema.json).
`verify_deception_lifecycle_review` reproduces it from the original plan,
events, and review time. This checks internal consistency, not source
authenticity or actual state. The report explicitly leaves approval, removal
testing, token privilege, alert delivery, and independent review unverified.
No placement, notification, token issuance, target interaction, authorization,
or qualification effect occurs.
