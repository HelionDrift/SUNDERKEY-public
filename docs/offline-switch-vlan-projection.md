# Supplied Switch VLAN Projection

The partial R0 component `network_supplied_switch_vlan_projection` belongs to
`AOE-GC-D13-S04`, under `AOE-GC-D13-CMD` with independent validator
`AOE-HQ-19`. It projects one declared local switch model. It does not replace
the specialist's candidate package, perform packet tests, or prove a live
network segmentation boundary.

The closed synthetic model names one switch, access or trunk ports, VLAN
membership, declared per-VLAN forwarding state, and specific ingress-to-egress
queries. Untagged ingress on an access port uses its access VLAN. Untagged
ingress on a trunk uses its declared native VLAN, if present. Tagged ingress
on a trunk uses the supplied tag. Tagged ingress on an access port is outside
this model and cannot produce a candidate. A candidate requires both declared
ports to be members of that VLAN and both to have a declared forwarding state.
The disposition remains a candidate under supplied declarations, not an
observed forwarding result. The model does not include MAC learning, private
VLANs, ACLs, overlays, routing, vendor behavior, or multi-switch paths.

`topology_complete`, `membership_complete`, and `stp_state_complete` are
caller declarations, not authenticated facts. If any is false, every query is
unknown. A no-candidate result means only that the supplied model lacks a
path under these narrow rules. It is not evidence that live traffic is
isolated. The component rejects duplicate port or query IDs, undeclared
ports, out-of-range or duplicate VLANs, inconsistent native membership,
invalid forwarding membership, and non-synthetic identifiers.

The report retains the complete original model, its digest, per-query
dispositions, limits, and explicit no-effect flags. Verification requires a
separately supplied original model. A modified report, changed source, or
self-attested report is rejected. The fixture is
[`examples/offline-switch-vlan-component.json`](../examples/offline-switch-vlan-component.json).
No network, credential, filesystem, process, provider, target, finding,
qualification, or deployment authority is conferred.
