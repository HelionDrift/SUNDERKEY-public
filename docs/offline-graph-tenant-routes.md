# Supplied graph tenant routes

The `AOE-GB-D07-S03` partial specialist projects directed routes from a
caller-declared tenant node through caller-declared graph edges. It distinguishes
routes made only of `declared_open` edges, routes that require an `unknown`
edge, and targets without a supplied route. A target in another declared
tenant receives the `declared_cross_tenant_route` label only when all selected
edges are declared open. This is a model consistency observation, not proof of
query access or exposure.

The exact native JSON model declares `schema_version: 1`,
`semantics_profile: supplied-graph-tenant-routes-v1`, a principal tenant, a
start node in that tenant, a graph-completeness boolean, up to 128 nodes, 512
directed edges, and 16 target objectives. Nodes and tenants use opaque digest
references. Traversal labels are limited to `declared_open`,
`declared_blocked`, and `unknown`. The projection chooses a deterministic
shortest route by edge identifier and retains the selected edge identifiers.
When no route is supplied, an incomplete graph remains unknown. Input size,
structure, traversal, and output size are bounded. The typed report replays
against the original model and rejects changed input.

Node identity, tenancy, edge visibility, and graph completeness are supplied
without authentication. This projection does not model database roles, row or
property policy, query language semantics, graph engine behavior, or live
target state. It never contacts a database, provider, credential, network, or
target, and grants no action authority or qualification. The
[synthetic example](../examples/offline-graph-tenant-routes-component.json)
contains only fictitious opaque references.
