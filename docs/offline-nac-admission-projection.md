# Supplied NAC Admission Projection

The partial R0 component `network_supplied_nac_admission_consistency` belongs
to `AOE-GC-D13-S07`, under `AOE-GC-D13-CMD` with independent validator
`AOE-HQ-19`. It compares synthetic admission, controlled-port and numeric VLAN
assignment assertions with an explicit caller-supplied policy. It does not
replace the full NAC and 802.1X specialist package.

[IEEE 802.1X](https://standards.ieee.org/ieee/802.1X/7345/) describes
port-based network access control. [RFC 3580](https://www.rfc-editor.org/rfc/rfc3580)
describes RADIUS VLAN assignment attributes. This component does not parse a
RADIUS packet or implement either standard. It uses the narrow labels
`tunnel_type=vlan`, `tunnel_medium_type=ieee802` and an integer
`tunnel_private_group_vlan` only as supplied model fields. The caller separately
declares a port state, assigned VLAN, configured VLAN list and policy
expectations for accepted and rejected sessions.

The result can identify a difference between those declarations. For example,
under a caller policy requiring rejected sessions to remain unauthorized, a
rejected session declared authorized is a candidate difference. Under a policy
requiring VLAN assignment on acceptance, an incomplete attribute trio,
unconfigured VLAN or differing assigned VLAN is also a candidate. These are
not universal security rules. Fallback modes, multi-host ports,
reauthentication and vendor policy can change real behavior. A supplied
difference proves neither a live bypass nor reachability.

`policy_complete`, `sessions_complete` and `configured_vlans_complete` are
unauthenticated caller assertions. If any is false, the component withholds all
issue projections. The closed model rejects duplicate session or VLAN IDs,
invalid VLAN ranges, non-synthetic identifiers and undeclared fields. It
accepts no packet bytes, credentials or target address. The unsigned report
retains the original model and digest, per-session dispositions, limitations
and explicit no-effect flags. Verification requires separate original-model
replay. The fixture is
[`examples/offline-nac-admission-component.json`](../examples/offline-nac-admission-component.json).
No network, credential, filesystem, process, provider, target, finding,
qualification or deployment authority is conferred.
