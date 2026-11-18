# Supplied Kerberos Realm-Path Projection

This R0 offline component adds partial algorithm coverage for specialist
`AOE-GA-D03-S06`, capability `army.ga.d03.s06`, vector
`AV-GA-D03-S06-01`, work package `IWP2-AOE-GA-D03-S06`, and wave `IW2-007`.
The domain commander is `AOE-GA-D03-CMD`, and independent validation is
assigned to `AOE-HQ-19`. It is not a completed candidate or qualified agent.

The version 1 model accepts synthetic ticket, realm, and service labels,
caller-declared ticket windows, a transited-realm list, a trusted-realm set,
completeness flags, and reported outcomes. The transited-policy concept is
described in [RFC 4120](https://www.rfc-editor.org/info/rfc4120/). This
component does not parse tickets or implement Kerberos. All times are
bounded logical ticks, not KDC or service clocks.

An absent ticket in a complete inventory, declared service realm or service
ID mismatch, observation outside the ticket window, or a declared untrusted
client or transited realm in a complete policy yields a deny projection.
Incomplete policy, ordering, ticket inventory, or realm policy remains
unknown where relevant. A declared trusted path also remains unknown: the
realm list is not authenticated, the ticket is not cryptographically
verified, and Kerberos authentication is not application authorization.

`analyze_supplied_kerberos_realm_path` emits an unsigned content-addressed
report. Verification replays a separately retained original model through
`verify_supplied_kerberos_realm_path` or its bounded JSON-byte variant. The
report's embedded source cannot authenticate itself. A synthetic dispatcher
input is in
[`offline-kerberos-realm-path-component.json`](../examples/offline-kerberos-realm-path-component.json).

A candidate mismatch is not observed authentication or a verified
vulnerability. No ticket bytes, KDC exchange, network, provider, target,
credential, process, filesystem, or execution action occurs.
