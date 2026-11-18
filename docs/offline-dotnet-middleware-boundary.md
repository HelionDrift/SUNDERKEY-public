# Supplied .NET middleware ordering projection

This R0 partial component serves existing specialist `AOE-GB-D05-S07`,
capability `army.gb.d05.s07`, vector `AV-GB-D05-S07-01`, package
`IWP2-AOE-GB-D05-S07`, and wave `IW2-007`. It adds partial offline evidence
only. It does not complete the specialist, candidate, qualification,
independent-validation, or live-use gate.

`analyze_dotnet_middleware_boundary(*, source_content: bytes, source_id: str)`
accepts one bounded UTF-8 JSON declaration with exactly `schema_version`
(`v1`), `declarations_complete`, `pipeline_kind`
(`explicit_endpoint_routing`), `middleware`, and `routes`. Middleware entries
are supplied in order and label a unique ID with `routing`, `authentication`,
`authorization`, `endpoint`, or `other`. At most one of each modeled stage is
supported. Complete explicit pipelines require one routing and endpoint
stage. Routes declare an ID, inert exact ASCII path, and supplied
`requires_authorization` policy. The narrow model does not represent branch
pipelines, implicit routing, policy handlers, endpoint metadata, or actual
requests.

For a complete supplied declaration set, a protected route is
`declared_order_satisfied` only if the authorization stage appears after
routing and before endpoint dispatch. A missing authorization stage or one
outside that window yields `candidate_declared_order_gap` with a specific
basis. A route not requiring authorization is `not_required`. Incomplete
declarations yield `unknown`. Authentication placement is retained as a
declaration but does not establish authorization or trigger a candidate gap
in this narrow model. These are candidate requirement comparisons, not
verified middleware behavior or findings.

The report binds exact source bytes by SHA-256, records per-route projections
and assessment counts, and fixes every authority, execution, target, network,
provider, credential, deployment, routing, and qualification effect to `none`.
`DotnetMiddlewareBoundaryReport.from_json` validates local report shape and
address only. `verify_dotnet_middleware_boundary` replays exact original
source bytes and compares the entire report. A readdressed report alone does
not prove source derivation or authenticity.

`analyze_supplied_dotnet_middleware_boundary(model)` is the catalog adapter.
Its exact native model has `source_id` and `source`; `component_fixture()`
returns a fresh synthetic source. The common-envelope example is
`examples/offline-dotnet-middleware-boundary-component.json`. Its R0 dry run
has empty network, filesystem, process, and credential resources. No target
interaction or live exploit occurs.
