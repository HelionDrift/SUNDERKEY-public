# Supplied API inventory drift projection

This R0 partial component belongs to existing specialist `AOE-GB-D06-S14`,
capability `army.gb.d06.s14`, vector `AV-GB-D06-S14-01`, package
`IWP2-AOE-GB-D06-S14`, and wave `IW2-005`. It contributes partial A7.4
offline evidence only, not specialist completion, qualification, or approval
for live use.

## Closed input and candidate boundary

`analyze_supplied_api_inventory_drift(model)` accepts exact native schema
version 1 with separately identified approved-inventory and route-manifest
sources. Each declares a scope ID and whether it is complete. The approved
inventory lists canonical API IDs, `vN` versions, declared `current`, `legacy`,
or `retired` lifecycle labels, and exact method/path routes. The manifest lists
declared deployments and routes with explicit active and enabled flags. IDs,
versions, methods, and literal paths are compared exactly. URL, path, or
version normalization is not inferred.

An enabled manifest route on a declared active deployment can become an
`undeclared_route_candidate` only when both sources declare completeness,
their scope IDs match, and its exact API/version/method/path tuple is absent
from the approved inventory. The same complete, scope-aligned premises are
required for a `legacy_route_candidate`, which also requires the exact route
to have a supplied `legacy` or `retired` lifecycle label. A supplied current
route is a narrow negative result for this check. Routes marked disabled or
attached to inactive deployments are excluded by those supplied flags.

If either source is incomplete or the scopes differ, active routes are
`unknown_source_scope_or_completeness`, not candidates. The completeness,
scope, deployment state, and lifecycle labels are caller declarations, not
authenticated target observations.

## Replay and effects

The deterministic report retains the supplied model, source IDs and SHA-256
addresses, per-route outcomes, candidates, unknowns, and uncertainty.
`verify_supplied_api_inventory_drift` rederives it against a separately
supplied original model. The checked synthetic common R0 envelope is
`examples/offline-api-inventory-drift-component.json`.

The analyzer does not scan, request a URL, inspect a deployment, start a
process, resolve credentials, or interact with a target. Candidate rows are
supplied-record discrepancies, not active discovery, verified exposure, or a
live shadow-API claim.
