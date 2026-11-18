# Supplied directory trust paths

The `AOE-GC-D11-S06` partial specialist projects caller-supplied directed
trust declarations across opaque domain references. Disabled edges are not
traversed. A supplied nonchainable edge can end a path but cannot be extended.
The report preserves selective-authentication and SID-filtering labels as
unverified gates, not evaluated controls. It distinguishes a caller-declared
complete inventory with no supplied path from an incomplete inventory.

The exact native JSON model declares `schema_version: 1`,
`semantics_profile: supplied-directory-trust-paths-v1`, an inventory-complete
boolean, two to 64 opaque domains, up to 256 directed trust declarations, and
one to 16 queries. Each trust has a unique edge ID, source, destination,
enabled and chainable flags, and two gate labels. Inputs, graph traversal,
and reports are bounded. The typed report can be replayed against current
supplied input.

Domains, direction, state, chainability, gates, and completeness are caller
assertions. A supplied path does not prove forest or domain trust
configuration, authentication, authorization, or lateral access. An absent
path does not prove real absence. No directory, credential, service, network,
or target is contacted. The component grants no action authority or
qualification. The [synthetic example](../examples/offline-directory-trust-paths-component.json)
uses only fictitious opaque references.
