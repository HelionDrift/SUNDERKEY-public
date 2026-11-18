# Supplied IP prefix and origin-ASN mapping

The `AOE-GA-D01-S04` partial component compares a bounded caller-supplied
route snapshot with caller-supplied IP address queries. Its deterministic
algorithm selects the longest matching canonical CIDR prefix of the same IP
family and reports the distinct origin ASNs declared by those selected rows.
One ASN yields `single_supplied_origin`; multiple ASNs yield
`conflicting_supplied_origins`. No matching row yields
`not_in_supplied_table`, which is not evidence that an address or route is
absent on any real network.

The model has exact fields `schema_version: 1`,
`semantics_profile: supplied-prefix-origin-snapshot-v1`, `routes`, and
`queries`. It accepts one to 512 routes and one to 64 queries. Each route
has a unique `route_id`, canonical `prefix`, 32-bit positive `origin_asn`,
and caller-declared `source_id`. Duplicate prefix/ASN/source observations are
refused. Each query has a unique `query_id` and canonical IP `address`.
The report retains selected route and source labels, flags and explicit
no-effect boundaries. Its typed wrapper replays the embedded model, and
verification independently rederives it from the supplied model.

This is a partial offline specialist algorithm, not a completed candidate.
Source labels and routes are not authenticated. The result does not establish
ASN ownership, RPKI validity, BGP path selection, actual route reachability,
target existence, or a finding. No scanning, BGP session, provider call,
credential use, target interaction, routing, qualification, or publication
occurs. The [synthetic example](../examples/offline-prefix-origin-component.json)
uses documentation address space and private ASNs.
