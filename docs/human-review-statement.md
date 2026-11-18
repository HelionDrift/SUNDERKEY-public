# Offline Human Review Statement

This V9.14 companion captures a signed historical opinion about one case and
one reviewer slot in a source-replayed human-escalation routing proposal. It
does not assign the proposed person, authenticate their identity or expertise,
grant evidence access, approve a finding, or authorize target activity.

## Exact Source Binding

`build_human_review_statement` recomputes the complete routing plan from its
supplied cases and roster before it selects a slot. The selected slot must be
`proposed` for the stated case, role, and reviewer. The statement binds the
tenant, plan, case, scope, evidence, roster entry, reviewer role, reviewer
reference, rationale digest, asserted review time, disposition, and pinned
public-key fingerprint. The time must fall within the proposal, case response,
and asserted reviewer-availability windows. A different case, role, reviewer,
source digest, or changed plan is rejected on verification.

The three opinions are `supports`, `challenges`, and
`insufficient_evidence`. None means accepted for publication or execution.
Only an external signer holds the private Ed25519 key. The reference exposes
domain-separated signing bytes and verifies a canonical base64url signature
against a caller-pinned public key. The checked record shape is in
[`human-review-statement-v1.schema.json`](../registry/schemas/human-review-statement-v1.schema.json).

## Custody Boundary

The caller must obtain the public key and its reviewer mapping through
independent, trusted custody. A valid signature proves possession of that
key, not the real person's identity, qualifications, conflict freedom, or
assignment acceptance. The roster and review time are caller assertions, not
live currentness evidence. Separate signed statements do not constitute an
independent multi-role approval bundle. Production use still needs verified
identity, source authentication, durable assignment and load accounting,
fresh conflict checks, secure evidence access, and governed disposition
admission. This record has no admission, assignment, authority, notification,
qualification, review-approval, or target-interaction effect.
