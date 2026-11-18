# Supplied search alias projection

The `AOE-GB-D07-S06` partial specialist compares caller-supplied alias routes,
index tenant labels, and declared tenant filters against an expected tenant.
It identifies supplied route alignment, index-label mismatch, an unscoped
shared-index declaration, or a route excluded by its declared filter. An alias
with no supplied route remains explicitly unassessed.

The exact native JSON model declares `schema_version: 1`,
`semantics_profile: supplied-search-alias-v1`, 1 to 128 opaque indexes, up to
256 routes, and 1 to 16 objectives. Index, alias, and tenant references are
opaque digests. This is an abstract declaration comparison, not an engine
query planner or a live search result. The typed report replays from the
bounded model.

Index ownership, route, and filter assertions are unauthenticated. A mismatch
or unscoped shared index does not prove cross-tenant document exposure. No
index, provider, service, credential, network, or target is contacted. The
report grants no action authority or qualification. The
[synthetic example](../examples/offline-search-alias-component.json) uses only
fictitious opaque references.
