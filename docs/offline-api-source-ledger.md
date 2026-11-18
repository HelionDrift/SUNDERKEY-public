# Offline API source ledger

The source ledger retains content-addressed custody metadata across successive
offline API assessment batches. A batch verifier already rejects duplicated
evidence and HTTP response receipt references within one batch. The ledger
extends that check across batches in the same mission, scope, and reference
adapter manifest.

`append_offline_api_source_batch` first reproduces the new batch from its
typed invocation, evidence, result, and native adapter. It verifies any prior
ledger, then rejects reused batch, case, invocation, evidence, or receipt
identities. Receipt-sourced batches must also retain one scope digest, stable
target digests, and stable session-to-principal mappings. A batch cannot mix
receipt-sourced and unsourced cases. Each case retains the digest of the batch
that introduced it, and batch digests retain append order.

`verify_offline_api_source_ledger` is an archive-integrity check. It checks the
closed shape, replay constraints, cross-case context, batch links, and the
ledger content address. It does not reproduce cases without their original
sources and does not authenticate the producer of an HTTP receipt. Keep those
sources and independently verified custody records outside this compact
ledger. Verification of this document alone grants no current authority,
execution, qualification, or finding publication.

For retest, append the new batch to the prior ledger before using the new
observations in a child world snapshot. This catches reused source identities
that a single-batch verifier cannot see. The resulting child world still
contains hypotheses and negative observations, not established exploitation
paths or independently reviewed findings.

The opt-in `offline_api_source_attestation` module signs a receipt-sourced
ledger with a caller-pinned local Ed25519 key. Historical verification still
works after the signed window expires; freshness rehearsal separately requires
the expected mission, scope, scope digest and a time inside that window.
Neither establishes live currentness or approved positive use.

At signature consumption, the exact `OfflineSourceKeyBinding` family is
required. Its current native key and producer identifiers and Ed25519 public
key are captured and revalidated before comparison or use. Wire metadata,
digests, timestamps and signature strings must be native JSON strings, as
must mapping keys and effect values. The effects object must be a native
JSON object. Freshness context receives the same native primitive checks.
Historical results remain detached canonical JSON. Native-key read-only
document views are supported, and ordinary JSON attestation and rehearsal
identities are unchanged. These checks reject caller string hooks and malformed
reassigned bindings, not general arbitrary-mapping or concurrent mutation.

Before attestation replay, ledger context keys, mode, identifiers and digests
must be native strings. The ledger verifier itself also checks native keys
in ledger, case, session and effects mappings, native mode and effects, and
native identity and digest primitives before sets or comparison. Content
address hooks cannot conceal a changed mission while retaining the old
ledger identity. Ordinary JSON ledger identities and both source modes are
unchanged.
