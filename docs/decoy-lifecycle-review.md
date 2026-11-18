# Synthetic decoy lifecycle review

This repository-only V9.8 slice reviews caller-supplied lifecycle metadata
for a synthetic decoy. An owner approval names one opaque decoy reference,
one opaque placement surface, tenant, scope, owner, and expiry no more than 30
days after approval. Events assert placement, trigger, revocation, or removal
and carry exact approval and evidence digests. The reviewer orders events by
time, deduplicates identical records, rejects conflicting event IDs and
ambiguous timestamps, and checks lifecycle transitions.

The output is an asserted state, not proof that a decoy was actually placed,
triggered, revoked, or removed. A trigger requires independent review and is
not proof of an attacker. A post-expiry trigger receives an additional flag.
Expired or revoked asserted placements require removal evidence, and asserted
removal itself requires external verification. False-trigger adjudication
remains a human and telemetry workflow outside this module.

Only opaque references are accepted. Decoy references must describe synthetic
tokens and must not encode real credentials, secrets, or sensitive data. The
module validates reference shape, not origin, signatures, owner identity, or
evidence authenticity. It does not issue a token, deploy or monitor a decoy,
send an alert, contact a target, revoke a token, or remove a placement.

Production completion requires authenticated owner approval, safe token
generation and custody, deployment adapters, alert integration, retention,
false-trigger review, expiry enforcement, revocation propagation, removal
receipts, and independent cleanup verification. This review never grants
authority for those actions.
