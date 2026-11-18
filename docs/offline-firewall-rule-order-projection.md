# Supplied Firewall Rule-Order Projection

The partial R0 component `network_supplied_firewall_rule_order` belongs to
`AOE-GC-D13-S05`, under `AOE-GC-D13-CMD` with independent validator
`AOE-HQ-19`. It compares synthetic zone, protocol and destination-port queries
with a caller-supplied ordered rule list and explicit default action. The first
matching declared rule determines the local allow or deny projection. It does
not replace the full firewall, NAT, proxy or VPN specialist package.

Each rule has an exact synthetic ingress and egress zone, TCP or UDP protocol,
inclusive destination-port interval, and declared action. The model does not
interpret IP prefixes, stateful reply paths, NAT translations, proxy policy,
VPN routing, nested policies, vendor-specific behavior or installed device
configuration. It cannot prove live reachability or isolation. A rule-order
change can alter the projection, but the supplied order is not observed.

`policy_complete`, `order_complete` and `match_semantics_complete` are caller
declarations. If any is false, all query decisions and matched-rule
attributions become unknown. The closed model rejects duplicate IDs,
out-of-range or reversed port intervals, unknown fields and non-synthetic
identifiers. It accepts no address, credential or packet payload.

The unsigned report retains the original model, its digest, per-query results,
explicit no-effect flags and limitations. Verification requires separate
replay from the original model, not a report's own assertions. The fixture is
[`examples/offline-firewall-rule-order-component.json`](../examples/offline-firewall-rule-order-component.json).
No network, credential, filesystem, process, provider, target, finding,
qualification or deployment authority is conferred.
