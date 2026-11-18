# Supplied Certificate-Authentication Metadata Projection

This R0 offline component adds partial algorithm coverage for specialist
`AOE-GA-D03-S07`, capability `army.ga.d03.s07`, vector
`AV-GA-D03-S07-01`, work package `IWP2-AOE-GA-D03-S07`, and wave `IW2-008`.
The domain commander is `AOE-GA-D03-CMD`, and independent validation is
assigned to `AOE-HQ-19`. It is not a completed candidate or qualified agent.

The version 1 model accepts synthetic certificate, issuer, and subject
labels with caller-declared validity windows, revocation ticks, client-auth
usage, direct trusted-issuer membership, and reported outcomes. Validity
and revocation are concepts from [RFC 5280](https://www.rfc-editor.org/info/rfc5280/),
but this component does not process X.509 certificates or implement RFC 5280
path validation. All times are bounded logical ticks, not service clocks.

An absent certificate in a complete inventory, mismatched declared subject,
missing client-auth usage, observation outside the declared validity window,
observation after declared revocation, or issuer absent from a complete trust
set yields a declared deny projection. Incomplete policy, ordering, issuer,
or certificate inventories remain unknown where relevant. If no negative
invariant applies, the projection remains unknown because no signature,
chain, revocation status, or effective authentication is verified.

`analyze_supplied_certificate_auth_metadata` emits an unsigned
content-addressed report. Verification replays a separately retained
original model through `verify_supplied_certificate_auth_metadata` or its
bounded JSON-byte variant. The report's embedded source cannot authenticate
itself. A synthetic dispatcher input is in
[`offline-certificate-auth-metadata-component.json`](../examples/offline-certificate-auth-metadata-component.json).

A candidate mismatch is not proof of effective certificate authentication
or a vulnerability. No certificate bytes, private key, public-key operation,
network, provider, target, credential, process, or filesystem action occurs.
