# Supplied API property authorization projection

This R0 partial component serves existing specialist `AOE-GB-D06-S11`,
capability `army.gb.d06.s11`, vector `AV-GB-D06-S11-01`, and wave `IW2-003`.
It compares two supplied JSON object projections under one supplied property
write policy. It does not send a request, authenticate a role or policy, observe
a server, verify a finding, or complete the candidate's six development gates.

## Supplied sources

`analyze_property_authorization` accepts bounded UTF-8 JSON bytes for a
before object, an after object, and a policy, with three distinct source IDs.
Duplicate JSON keys, unsupported numbers, unbounded depth, invalid pointer
escapes, and open policy fields are rejected. The policy is exactly version
`v1`, a declared actor `role`, a native `complete` boolean, and a bounded list
of `{path, write_roles}` records. Each `path` is an exact JSON Pointer. The
catalog adapter `analyze_supplied_property_authorization(model)` accepts those
same three sources as native JSON objects plus their IDs, then canonicalizes
each object before the byte-level comparison.

Every changed path is labeled `declared_permitted`, `declared_prohibited`, or
`uncertain`. An explicit rule takes precedence. An unlisted path is prohibited
only when the caller declares the policy complete; otherwise it is uncertain.
Addition, removal, replacement, nested keys, and absent versus null remain
distinct. These labels describe a contradiction or agreement among supplied
premises, not actual server-side authorization. The report omits body values
and retains source digests, byte counts, paths, role, counts, limitations, and
no-effect flags.

## Replay and local use

`verify_property_authorization` reanalyzes separately supplied original bytes
and IDs. The common component verifier replays the complete original request
against the current source-bound catalog. A self-addressed report alone is not
proof of source provenance or authorization. The checked synthetic request is
`examples/offline-property-authorization-component.json` and may be run only
through the deny-all offline component or common-task interface. No network,
filesystem, process, credential, target, provider, qualification, or routing
effect is granted.
