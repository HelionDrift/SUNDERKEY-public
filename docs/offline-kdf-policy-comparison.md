# Supplied KDF Policy Comparison

This R0 offline component adds partial algorithm coverage for specialist
`AOE-GE-D22-S04`, capability `army.ge.d22.s04`, vector
`AV-GE-D22-S04-01`, work package `IWP2-AOE-GE-D22-S04`, and wave `IW2-017`.
The domain commander is `AOE-GE-D22-CMD`, and independent validation is
assigned to `AOE-HQ-19`. It is not a completed candidate or qualified agent.

The version 1 model compares caller-supplied active KDF configuration numbers
with caller-supplied per-algorithm policy minima. It supports exact parameter
shapes for Argon2id, scrypt, and PBKDF2-SHA256. A missing allowed algorithm
or a numeric value below its declared minimum is a candidate local-policy
mismatch. Retired records are not assessed, and incomplete declarations remain
unknown. Meeting supplied minima does not prove cryptographic strength.

The example numbers are synthetic policy fixtures, not recommendations or
current security standards. No password, password hash, salt value,
credential, or KDF operation is accepted. The algorithm names and parameter
counts are declarations, not verified deployed settings.

`analyze_supplied_kdf_policy` emits an unsigned content-addressed report.
Verification replays a separately retained original model through
`verify_supplied_kdf_policy` or its bounded JSON-byte variant. The embedded
model cannot authenticate itself. A synthetic dispatcher input is in
[the component example](../examples/offline-kdf-policy-component.json).

No target, provider, credential, or live system is contacted. No finding,
positive use, or qualification occurs.
The [common-task integration](offline-crypto-policy-task.md) retains this
model separately from the nonce-label model under one inert commander task.
