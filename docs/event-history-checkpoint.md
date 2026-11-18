# Offline Event-History Checkpoint

The optional V9.3 checkpoint binds one verified local event-assessment journal
head to a caller-pinned Ed25519 public key and custody domain. It is an offline
reference contract for detecting a changed local head relative to a retained
checkpoint. It does not authenticate event sources or authorize a new
assessment.

## Signing and Verification

`build_event_history_checkpoint` replays the complete local
`OfflineEventAssessmentHistoryStore`, then binds its scope digest, head
sequence, head digest, a caller-asserted UTC observation time, custody domain,
and pinned key fingerprint. An external signer obtains domain-separated bytes
from `event_history_checkpoint_signing_bytes` and supplies a 64-byte Ed25519
signature encoded as unpadded base64url. The reference module neither handles
a private key nor sends a network request.

`verify_event_history_checkpoint` requires the same independently obtained
public key and expected domain. It rejects duplicate JSON keys, changed
content, a wrong signature, and any checkpoint that differs from the currently
replayed local head. An appended event therefore makes the old checkpoint
inapplicable to the new head. The exact record shape is in
`registry/schemas/event-history-checkpoint-v1.schema.json`.

## Custody and Product Boundary

The caller must obtain and pin the public key through independent custody.
The module does not attest the signer's identity, role, key custody, or the
truth of the asserted time. Retain the signed checkpoint outside the journal
and bind it to an independent monotonic or append-only custody system before
claiming long-term anti-rollback protection. A signer that signs rewritten
history, or a lost earlier checkpoint, defeats comparison against the earlier
head. This implementation does not supply that external custody system.

Checkpoint creation and verification have no admission, authority, network,
qualification, scheduling, or target-interaction effect. Live event intake,
idempotent delivery, authorization refresh, qualified runner integration, and
stop propagation remain separate work.
