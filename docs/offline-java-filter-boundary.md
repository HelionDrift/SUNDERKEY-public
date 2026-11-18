# Supplied Java servlet-filter coverage projection

This R0 partial component serves existing specialist `AOE-GB-D05-S06`, capability
`army.gb.d05.s06`, vector `AV-GB-D05-S06-01`, package
`IWP2-AOE-GB-D05-S06`, and wave `IW2-006`. It adds partial offline evidence
only. It does not complete the specialist, candidate, qualification,
independent-validation, or live-use gate.

`analyze_java_filter_boundary(*, source_content: bytes, source_id: str)`
accepts one bounded UTF-8 JSON declaration with exactly `schema_version`
(`v1`), `declarations_complete`, `filters`, and `routes`. Each filter declares
an ID, kind (`authorization_guard` or `other`), exact route IDs, and servlet
dispatcher types (`REQUEST`, `FORWARD`, `INCLUDE`, `ERROR`, or `ASYNC`). Each
route declares an ID, inert exact ASCII path, dispatcher type, and whether a
guard is required by the supplied policy. The model deliberately does not
interpret servlet URL patterns, filter chains, framework configuration, or
executed requests. The supplied `authorization_guard` label is not proof of
enforcement. Route IDs are unique; the same path may be declared under
different dispatcher types, while an identical path-dispatcher pair is
rejected. This represents separate supplied views of one inert path, not
path matching or evidence that either dispatch occurs.

For a complete supplied declaration set, a guarded route receives
`declared_coverage` only if a guard is mapped to its exact route ID and
dispatcher type. A mapped guard lacking that dispatcher yields
`candidate_declared_coverage_gap` with `guard_dispatcher_absent`. No mapped
guard yields the same candidate status with `guard_route_absent`. An unguarded
route is `not_required` under the supplied requirement. An incomplete set is
`unknown`, even if a guard appears in the partial declarations. These are
candidate requirement comparisons, not verified servlet behavior or findings.

The report binds exact source bytes by SHA-256, records per-route projections
and assessment counts, and fixes every authority, execution, target, network,
provider, credential, deployment, routing, and qualification effect to `none`.
`JavaFilterBoundaryReport.from_json` validates local report shape and address
only. `verify_java_filter_boundary` replays exact original source bytes and
compares the entire report. A readdressed report alone does not prove source
derivation or authenticity.

`analyze_supplied_java_filter_boundary(model)` is the catalog adapter. Its
exact native model has `source_id` and `source`; `component_fixture()` returns
a fresh synthetic source. The common-envelope example is
`examples/offline-java-filter-boundary-component.json`. Its R0 dry run has
empty network, filesystem, process, and credential resources. No target
interaction or live exploit occurs.
