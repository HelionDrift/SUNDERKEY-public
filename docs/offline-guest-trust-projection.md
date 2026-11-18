# Supplied B2B Guest-Trust Projection

This R0 offline component adds partial algorithm coverage for specialist
`AOE-GA-D03-S09`, capability `army.ga.d03.s09`, vector
`AV-GA-D03-S09-01`, work package `IWP2-AOE-GA-D03-S09`, and wave `IW2-010`.
The domain commander is `AOE-GA-D03-CMD`, and independent validation is
assigned to `AOE-HQ-19`. It is not a completed candidate or qualified agent.

The version 1 model accepts only synthetic tenant and guest labels, declared
invitations, active states, direct home-to-resource trust rules, completeness
flags, and reported outcomes. An absent guest in a complete inventory, an
inactive or uninvited guest, a different resource tenant, or a disabled or
absent trust in a complete inventory yields a declared deny projection.
Incomplete policy, guest inventory, or trust inventory remains unknown.
An enabled direct trust remains unknown because no federation exchange,
identity proof, role assignment, or resource access is verified.

`analyze_supplied_guest_trust` emits an unsigned content-addressed report.
Verification replays a separately retained original model through
`verify_supplied_guest_trust` or its bounded JSON-byte variant. The report's
embedded source cannot authenticate itself. A synthetic dispatcher input is
in [`offline-guest-trust-component.json`](../examples/offline-guest-trust-component.json).

This is an exact direct-trust model only. It does not expand transitive
federation or evaluate provider-specific guest policy. A candidate mismatch
is not effective guest access or a verified vulnerability. No network,
provider, target, credential, process, filesystem, or execution action occurs.
