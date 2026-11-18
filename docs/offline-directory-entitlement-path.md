# Supplied directory entitlement path

The `AOE-GC-D11-S01` partial specialist projects a caller-supplied source
principal through explicit group member-of edges to abstract resource grants.
For each requested resource and right label, it selects the shortest supplied
membership chain and terminal grant. Cycles terminate. If no path is supplied,
the report distinguishes a caller-declared complete graph from an incomplete
one. Neither state proves real path absence.

The exact native JSON model declares `schema_version: 1`,
`semantics_profile: supplied-directory-entitlement-path-v1`, an opaque source
principal, a supplied graph-completeness boolean, up to 64 opaque groups, 256
memberships, 256 grants, and 16 objectives. Each edge has a unique ID. Grants
and objectives use only `declared_read`, `declared_write`, or
`declared_control` labels. Inputs, traversal, and report size are bounded.
The typed report can be replayed against current supplied input.

Principal, group, membership, grant, and completeness statements are caller
assertions. The projection does not implement AD token expansion, deny ACEs,
SIDs, inheritance, trust, policy, or effective access. A supplied path is a
review hypothesis, not proof of a live access path or vulnerability. No
directory, credential, service, network, or target is contacted. It grants no
action authority or qualification. The [synthetic example](../examples/offline-directory-entitlement-path-component.json)
uses only fictitious opaque references.
