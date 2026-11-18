# Supplied Symmetric Nonce Reuse Projection

This R0 offline component adds partial algorithm coverage for specialist
`AOE-GE-D22-S05`, capability `army.ge.d22.s05`, vector
`AV-GE-D22-S05-01`, work package `IWP2-AOE-GE-D22-S05`, and wave `IW2-018`.
The domain commander is `AOE-GE-D22-CMD`, and independent validation is
assigned to `AOE-HQ-19`. It is not a completed candidate or qualified agent.

The version 1 model compares only synthetic key, mode, and nonce labels in a
caller-supplied ordered record list. If the caller declares a unique-nonce
policy, a second encryption record with the same key, mode, and nonce label
is a candidate declared reuse conflict. Decryption records do not consume an
encryption nonce slot. Different key or mode labels are not equated. This
does not assess cross-mode safety or prove actual key or nonce equality.

Incomplete policy, record coverage, or ordering leaves all dispositions
unknown. `analyze_supplied_symmetric_nonce_reuse` emits an unsigned
content-addressed report. Verification replays a separately retained
original model through `verify_supplied_symmetric_nonce_reuse` or its
bounded JSON-byte variant. The embedded model cannot authenticate itself.
A synthetic dispatcher input is in
[the component example](../examples/offline-symmetric-nonce-component.json).

No key bytes, nonce values, plaintext, ciphertext, credentials, or target
responses are processed. No cryptographic operation, finding publication,
positive use, or qualification occurs.
The [common-task integration](offline-crypto-policy-task.md) retains this
model separately from the KDF policy model under one inert commander task.
