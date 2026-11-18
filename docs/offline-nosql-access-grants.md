# Supplied NoSQL exact access-grant projection

This R0 component belongs to `AOE-GB-D07-S02`, capability
`army.gb.d07.s02`, vector `AV-GB-D07-S02-01`, package
`IWP2-AOE-GB-D07-S02`, and scheduled wave `IW2-002`. Its component ID is
`data_supplied_nosql_access_grants_projection`. It adds partial offline
evidence only and does not qualify the specialist.

The schema version 1 model declares exact collection IDs, role and direct
principal grants for `read`, `write` and `delete`, role memberships, and
supplied admission decisions. It separately requires complete role grants,
direct grants, collection inventory and alternate grant paths. The last
assertion means no unmodeled grant mechanism can authorize the check. A check
declares whether its policy is exact or has wildcard or dynamic semantics.
The latter always projects `unknown`; wildcard grants are not silently
interpreted as exact ones.

With all premises complete, an exact role or direct grant yields expected
allow. Only absence from both complete grant sets, with alternate paths
explicitly ruled out, yields expected deny. Supplied allow against declared deny is a
candidate declaration contradiction. Supplied deny against declared allow is
an availability contradiction, not a security bypass. Matching decisions are
only internally consistent declarations. No document-level conditions,
inherited policy or actual database response is inferred.

`analyze_supplied_nosql_access_grants` accepts a native model. Its `_bytes`
variant accepts bounded ASCII JSON. The report embeds its source model and
domain-separated addresses. `from_json` replays that embedded model;
`verify_supplied_nosql_access_grants_analysis` additionally compares a
separately supplied original. The synthetic R0 request is
`examples/offline-nosql-access-grants-component.json`.

No database, credential, network, process, provider or target is accessed.
The report does not establish actual collection access, exploitability,
authority, positive use, a live finding or qualification.
