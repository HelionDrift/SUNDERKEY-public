# Supplied Domain Controller Topology Declarations

The `AOE-GC-D11-S07` partial specialist, component
`supplied_dc_topology_declarations`, compares caller-supplied controller backup
ages and expected directed links with a caller-supplied local age limit and
declared directed links. It can identify an age above that local limit, a
missing expected link, or an expected link declared disabled. A matching
declaration does not prove replication, connectivity, backup recoverability,
or directory health.

The exact native JSON model has `schema_version: 1`, a bounded `source_id`,
`inventory_complete`, `policy`, one to 64 `controllers`, and bounded
`expected_links` and `declared_links`. Controller references are opaque
SHA-256 references; roles are `writable` and `read_only`. Link direction is
preserved. Incomplete inventory yields `unknown`, no candidates, and one
unknown row for each controller and expected link. Replay verification
recomputes the report from the separately supplied original model.

The component does not read a directory database or backup, query a domain
controller, use credentials, contact a network or target, publish a finding,
or grant qualification. The
[synthetic example](../examples/offline-dc-topology-declarations-component.json)
uses fictitious digest references only.
