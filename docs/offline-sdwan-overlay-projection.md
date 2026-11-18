# Supplied SD-WAN Overlay Projection

The partial R0 component `network_supplied_sdwan_overlay_projection` belongs
to `AOE-GC-D13-S21`, under `AOE-GC-D13-CMD` with independent validator
`AOE-HQ-19`. It compares synthetic, directed site links and explicit
source-target policy pairs against caller-declared reachability. It does not
replace the full SASE, SD-WAN and zero-trust network-fabric specialist package.

The component computes a deterministic shortest path over links declared
`up`, then separately checks whether the caller included the exact
source-target pair in `allowed_pairs`. Both predicates must hold for a
projected `reachable` result. A policy allowance is not treated as evidence
of a route, and a route is not treated as evidence of policy permission. The
model does not evaluate per-hop policy, asymmetric return paths, route
advertisements, quality of service, tunnels or a vendor controller. The
reported path is a sequence of synthetic IDs, not a packet trace.

`sites_complete`, `links_complete`, `policy_complete` and `queries_complete`
are unauthenticated caller assertions. If any is false, the component
withholds every route and policy projection. The closed model rejects
duplicate sites and links, unknown site references, self-queries, real-looking
site IDs, undeclared address and secret fields. Synthetic labels do not prove
that the caller's underlying information is synthetic. The fixture is
[`examples/offline-sdwan-overlay-component.json`](../examples/offline-sdwan-overlay-component.json).

The unsigned report retains the original model and digest, per-query
dispositions, limitations and explicit no-effect flags. Verification requires
separate original-model replay. A declared difference does not prove a live
route, policy enforcement, reachable target or exploitable path. No network,
credential, filesystem, process, provider, target, finding, qualification or
deployment authority is conferred.
