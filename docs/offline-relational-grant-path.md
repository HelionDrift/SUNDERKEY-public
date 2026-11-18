# Supplied relational grant paths

The `AOE-GB-D07-S01` partial specialist projects an opaque principal through
explicit role-membership edges to supplied relation grants. For each requested
relation and abstract privilege it selects the shortest declared path. A
missing path remains unknown when the caller marks the graph incomplete.

The exact native JSON model declares `schema_version: 1`,
`semantics_profile: supplied-relational-grant-path-v1`, an opaque principal,
up to 64 roles, 256 membership edges, 256 grant edges, and 16 objectives.
Privileges are only `declared_select`, `declared_insert`, `declared_update`,
and `declared_delete`. Inputs, traversal, and report size are bounded, and the
typed report replays against the supplied model.

Role and grant assertions are unauthenticated. The projection omits ownership,
deny rules, row or column policy, schema inheritance, and vendor-specific
effective privilege rules. A supplied path is not proof of database access or
vulnerability. No SQL, database client, credential, network, or target is
contacted. The report grants no action authority or qualification. The
[synthetic example](../examples/offline-relational-grant-path-component.json)
uses only fictitious opaque references.
