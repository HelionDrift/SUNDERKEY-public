# Supplied opaque credential-exposure review

The `AOE-GA-D01-S08` partial specialist wraps the existing
[credential-exposure triage](credential-exposure-triage.md) in a bounded,
source-replayed offline component. It accepts one tenant and scope, one to
128 opaque exposure signals, at most 128 supplied consent records, and one
caller-declared review time. The underlying triage distinguishes a
`human_review_candidate`, `blocked_missing_current_consent`, and
`stale_signal`. Its output remains a review plan, not proof of credential
validity, compromise, or actual consent.

The model has exact fields `schema_version: 1`,
`semantics_profile: supplied-opaque-credential-exposure-v1`, `tenant_id`,
`scope_sha256`, `reviewed_at`, `signals`, and `consents`. Signal and consent
fields are closed. Principal and credential references must be opaque
digest-shaped values. Their actual origin from independent random identifiers
is not proven in this offline component and must not be derived from secret
or password bytes. Raw passwords, reusable hashes, and unknown signal fields
are not accepted. The typed report replays its source model and verifies
current input independently.

Caller-supplied source digests, feed references, timestamps and consent
records are not authenticated. No feed access, credential resolution, login,
password audit, rotation, target interaction, qualification, or publication
occurs. A review candidate does not authorize any of those actions. The
[synthetic example](../examples/offline-credential-exposure-component.json)
uses fixture-only opaque identifiers.
