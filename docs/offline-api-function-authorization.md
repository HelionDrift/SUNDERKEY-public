# Supplied API function authorization differential

This R0 component belongs to profile `AOE-GB-D06-S10`, capability
`api.authorization.function-level`, vector `AV-GB-D06-S10-01`, package
`IWP2-AOE-GB-D06-S10`, and wave `IW2-002`. It contributes partial A7.4
evidence only. It does not complete or qualify the specialist.
Its component ID is `api_supplied_function_authorization_differential`.

The schema version 1 model supplies a bounded role list, subjects with
declared role membership, functions with a role-permission matrix, and
invocations with supplied outcomes. A complete matrix explicitly enumerates
every declared role. Under the model's stated any-role-allow rule, any known
`allow` among a subject's held roles permits the function; otherwise all
known held-role rules must be `deny` to derive denial. This is function-level
comparison only. It does not model object identity, property writes, URLs,
route matching, or target state.
Complete membership with no held roles derives denial under this explicit
any-role-allow rule; an incomplete role list remains unknown.

A supplied allowed invocation contrary to a complete declared denial, or a
supplied denied invocation contrary to a complete declared allowance, receives
only a `candidate_contradiction` label. Complete known role membership,
matrix rules, and invocation observation are required. Incomplete membership
or matrix, missing or unknown held-role rules, or an incomplete or unknown
outcome yields `unknown`, not a candidate. A match is only a match under the
supplied policy model.

`analyze_supplied_api_function_authorization` accepts a native model;
`analyze_supplied_api_function_authorization_bytes` accepts bounded ASCII JSON
bytes. `verify_supplied_api_function_authorization_analysis` rederives the
report against a separately supplied original model. Reports carry the exact
source model, domain-separated source and analysis addresses, bounds,
limitations, false verification flags, and `none` effects. The synthetic R0
request is `examples/offline-api-function-authorization-component.json`.

No request or server enforcement is observed. The component does not access
an API, execute an invocation, use credentials, contact a target, or claim a
live authorization bypass, exploitability, qualification, or positive use.
