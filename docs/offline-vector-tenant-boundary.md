# Supplied vector tenant and namespace boundary projection

This R0 component belongs to `AOE-GB-D07-S04`, capability
`army.gb.d07.s04`, vector `AV-GB-D07-S04-01`, package
`IWP2-AOE-GB-D07-S04`, and scheduled wave `IW2-004`. Its component ID is
`data_supplied_vector_tenant_boundary_projection`. It adds partial offline
evidence only and does not qualify the specialist.

The schema version 1 model declares exact namespace ownership and tenant
isolation requirements. A query declares the requester tenant, exact or
dynamic filter mode, filter tenant, and completeness of filter, context,
result snapshot and sharing/delegation policy. It must explicitly assert
`sharing_delegation_exception: none` for every returned record before a
candidate can be projected. `applies`, `unknown` or incomplete exception
policy yields `unknown`. Each returned record declares a namespace, tenant label and
metadata completeness. All are caller-supplied assertions. IDs are inert,
case-sensitive labels, not endpoints or database queries.

Only when inventory, namespace mapping and policy, exact same-tenant filter,
query context, result snapshot, no-exception policy and record metadata are complete does the
component compare a returned record's labels to the declared query boundary.
A different namespace or tenant yields
`candidate_declared_tenant_boundary_contradiction`; an exact match is only
internally consistent data. Where tenant isolation is not required, the
result is `isolation_not_required`. Dynamic or absent filters, aliases,
unknown labels and mismatched requester/filter ownership yield `unknown`.
Shared records and delegated access are not inferred.

`analyze_supplied_vector_tenant_boundary` accepts a native model; its
`_bytes` variant accepts bounded ASCII JSON. The report embeds its source
model and domain-separated addresses. `from_json` replays that source;
`verify_supplied_vector_tenant_boundary_analysis` additionally checks a
separately supplied original. The synthetic R0 request is
`examples/offline-vector-tenant-boundary-component.json`.

No vector search, filter execution, database access, credential, network,
process, provider or target interaction occurs. No actual cross-tenant
retrieval, exploitability, authority, positive use, live finding or
qualification is claimed.
