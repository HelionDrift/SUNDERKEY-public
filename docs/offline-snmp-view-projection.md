# Supplied SNMP View Projection

The partial R0 component `network_supplied_snmp_view_projection` belongs to
`AOE-GC-D13-S15`, under `AOE-GC-D13-CMD` with independent validator
`AOE-HQ-19`. It compares bounded synthetic principal-operation bindings,
numeric object-identifier prefixes and declared access decisions. It does not
replace the full SNMP and NETCONF specialist package.

[RFC 3415](https://www.rfc-editor.org/rfc/rfc3415) describes the SNMP
View-based Access Control Model, including groups, views and access policies.
This component is not a VACM implementation. Its closed subset accepts one
view binding per synthetic principal and operation, unmasked numeric prefix
rules, and a list of supplied queries. The longest matching prefix determines
inclusion; no matching prefix or binding projects denial. These are explicit
local model rules, not a claim about a device's configuration or RFC behavior.

`views_complete`, `bindings_complete` and `queries_complete` are
unauthenticated caller assertions. If any is false, the component withholds
every access projection. Duplicate view IDs, rule prefixes, bindings and query
IDs are rejected. No endpoint, packet, community string, key or credential
field is accepted. Synthetic labels do not prove the underlying data is
synthetic. The fixture is
[`examples/offline-snmp-view-component.json`](../examples/offline-snmp-view-component.json).

The unsigned report retains the original model and digest, per-query
dispositions, limitations and explicit no-effect flags. Verification requires
separate original-model replay. A declared difference does not prove an SNMP
response, authenticated access, a bypass or an exploitable path. No network,
credential, filesystem, process, provider, target, finding, qualification or
deployment authority is conferred.
