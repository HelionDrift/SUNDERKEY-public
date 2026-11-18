# Supplied Wi-Fi Policy Projection

The partial R0 component `network_supplied_wifi_policy_projection` belongs to
`AOE-GC-D13-S08`, under `AOE-GC-D13-CMD` with independent validator
`AOE-HQ-19`. It compares synthetic network declarations with an explicit
caller-supplied policy for security mode, protected-management-frame state and
guest client isolation. It does not replace the full Wi-Fi specialist package.

The caller lists allowed security modes and, separately, the modes for which
its own policy requires `pmf_state=required`. The caller also chooses whether
guest networks require declared client isolation. The component reports only
differences from those exact choices. It does not assert a universal Wi-Fi
configuration baseline or interpret a vendor configuration. In particular,
`capable` and `required` are distinct labels in the supplied model, not an
observed negotiation result.

`policy_complete` and `networks_complete` are unauthenticated caller
assertions. If either is false, the component withholds all issue projections.
The closed model accepts only synthetic IDs, bounded mode labels and boolean
declarations. It rejects duplicate network IDs, duplicate policy modes,
undeclared SSID or BSSID fields, passphrases and credentials. Synthetic ID
labels do not prove that the caller's underlying information is synthetic.
The fixture is
[`examples/offline-wifi-policy-component.json`](../examples/offline-wifi-policy-component.json).

The unsigned report retains the original model and digest, per-network
dispositions, limitations and explicit no-effect flags. Verification requires
separate original-model replay. No radio, association, authentication, PMF
behavior or client isolation is observed. A declared difference does not prove
a live weakness, reachable client or exploitable path. No network, credential,
filesystem, process, provider, target, finding, qualification or deployment
authority is conferred.
