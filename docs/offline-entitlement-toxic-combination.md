# Supplied entitlement toxic-combination projection

This R0 partial component serves specialist `AOE-GA-D03-S14`, capability
`army.ga.d03.s14`, vector `AV-GA-D03-S14-01`, package
`IWP2-AOE-GA-D03-S14`, and scheduled wave `IW2-015`. Its component ID is
`identity_supplied_entitlement_toxic_combination`. It contributes partial
offline evidence only. It does not qualify the specialist, validate an
account, or authorize live use.

`analyze_entitlement_toxic_combination(*, source_content: bytes,
source_id: str)` accepts bounded UTF-8 JSON with `schema_version` (`v1`),
five completeness/absence booleans, and closed arrays of roles, principals,
and toxic permission pairs. Roles declare exact grants and acyclic
inheritance. Principals declare role IDs. Each toxic pair declares two
distinct exact permission IDs that the supplied policy prohibits a single
principal from combining. Cyclic inheritance, unknown roles, duplicate
pairs, ambiguous IDs, unknown fields, and over-bound data are rejected.

The component computes exact transitive role closure and compares each
principal-pair membership. It emits
`candidate_declared_toxic_combination` only when both permissions appear in
that supplied closure and the graph, assignments, grants, policy, and absence
of dynamic entitlements are all explicitly complete. If any premise is
false, every comparison is `unknown`; a complete comparison without both
permissions is `declared_pair_not_present`. This is a policy-conflict
candidate, not proof of actual privileges, account reachability, or abuse.
It does not model contextual grants, conditional roles, denies, exceptions,
tenants, or runtime enforcement. If any such mechanism is relevant, the
corresponding completeness premise must be false.

The report binds exact source bytes by SHA-256 and includes per-pair
projections, counts, fixed no-effect fields, and explicit non-live flags.
`EntitlementToxicCombinationReport.from_json` checks local report shape and
address only. `verify_entitlement_toxic_combination` replays separately
supplied original bytes and compares the whole report. The exact native
adapter is `analyze_supplied_entitlement_toxic_combination({"source_id":
..., "source": ...})`. The synthetic common-envelope request is
`examples/offline-entitlement-toxic-combination-component.json` and uses
empty network, filesystem, process, and credential resources. No target,
network, provider, credential, process, or live exploit occurs.
