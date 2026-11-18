# Supplied web-route, UI and multitenancy policy projection

This R0 partial component serves existing specialist `AOE-GB-D05-S12`,
capability `web.access-control.multitenancy`, vector `AV-GB-D05-S12-01`,
package `IWP2-AOE-GB-D05-S12`, and wave `IW2-001`. It adds partial A7.4
offline evidence only. It does not complete the specialist, candidate, or any
qualification, independent-validation, or live-use gate.

`analyze_web_route_authorization(*, source_content: bytes, source_id: str)`
accepts one bounded UTF-8 JSON source with exactly `schema_version` (`v1`),
`facts_complete`, `policy_complete`, `principals`, `routes`, and
`observations`. Principals declare an ID, nullable tenant ID, and distinct
roles. Routes declare an ID, exact inert ASCII path, access mode (`public`,
`authenticated`, or `role`), nullable required role, and tenant scope (`none`
or `same_tenant`). Observations declare an ID, nullable principal ID (null
means anonymous), route ID, nullable resource tenant ID, supplied UI
visibility, and supplied server outcome. No URL or request is accepted or
constructed. Route paths are labels, not navigation targets or matched
patterns. Duplicate JSON keys, unknown fields, ambiguous paths, unsupported
values, and over-bound data are rejected.

When the supplied fact and policy sets are complete, the projection compares
exact role membership and tenant ID equality. Missing route or principal,
unknown tenant, or incomplete premises yields an unknown expected decision.
An anonymous principal is denied on a declared protected route. A known
missing role is denied even when its tenant is unknown. Public routes may not
declare tenant membership requirements. A supplied server outcome opposite a
resolved expected decision is `candidate_policy_contradiction`; an aligned
one is `declared_consistent`. Independently, UI visibility relative to the
expected access decision is recorded as `declared_ui_access_decision_same` or
`declared_ui_access_decision_differs`. These are neutral descriptions, not UI
policy findings: the source does not declare a UI exposure policy. UI visibility
never substitutes for a server outcome and does not establish enforcement.
An unknown server outcome or UI visibility leaves its respective assessment
unknown without erasing the other channel.

The report contains an exact source digest and byte count, per-observation
route and policy projections, separate UI and server counts, limitations,
and no-effect flags. `WebRouteAuthorizationReport.from_json` validates only
local report structure and address. It does not prove derivation or source
provenance. `verify_web_route_authorization(report, *, source_content,
source_id)` replays the exact original bytes and compares the entire report.

`analyze_supplied_web_route_authorization(model)` is the catalog adapter. Its
exact native model has `source_id` and `source`, with `source` matching
`component_fixture()`. The synthetic common-envelope example is
`examples/offline-web-route-authorization-component.json`. Its R0 dry run has
empty network, filesystem, process, and credential resources. No target,
network, browser, process, credential, execution, deployment, routing,
qualification, or authority effect is granted.
