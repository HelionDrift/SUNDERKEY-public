# Supplied SPIFFE ID Trust-Domain Projection

This R0 offline component adds partial algorithm coverage for specialist
`AOE-GA-D03-S10`, capability `army.ga.d03.s10`, vector
`AV-GA-D03-S10-01`, work package `IWP2-AOE-GA-D03-S10`, and wave `IW2-011`.
The domain commander is `AOE-GA-D03-CMD`, and independent validation is
assigned to `AOE-HQ-19`. It is not a completed candidate or qualified agent.

The version 1 model checks a bounded, 512-byte subset of supplied SPIFFE ID strings against the
[SPIFFE ID specification](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md)
and a caller-declared exact trust-domain set. It checks the `spiffe` scheme,
lowercase trust-domain characters, optional nonempty path segments, and
prohibited percent encoding, query, fragment, userinfo, port, empty segments,
and relative path segments. The scheme is parsed case-insensitively. The
component does not claim full SPIFFE URI-length interoperability, resolve a
network locator, or retrieve any trust material.

A malformed ID yields a declared deny projection. A well-formed ID outside
a complete declared trust-domain set also yields a declared deny projection.
An incomplete trust policy is unknown. A well-formed ID inside the declared
set remains unknown because syntax and domain membership do not validate an
SVID signature, a trust bundle, issuance, workload binding, or access.

`analyze_supplied_spiffe_id_trust` emits an unsigned content-addressed report.
Verification replays a separately retained original model through
`verify_supplied_spiffe_id_trust` or its bounded JSON-byte variant. The
report's embedded source cannot authenticate itself. A synthetic dispatcher
input is in
[`offline-spiffe-id-trust-projection-component.json`](../examples/offline-spiffe-id-trust-projection-component.json).

Trust domains, identities, policy completeness, and reported outcomes are
caller declarations. A candidate mismatch is not a verified trust bypass or
vulnerability. No SVID, certificate, private key, network, provider, target,
credential, process, or filesystem action occurs.
