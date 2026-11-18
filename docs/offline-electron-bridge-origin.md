# Supplied Electron renderer bridge-origin projection

This R0 component belongs to profile `AOE-GB-D08-S18`, capability
`army.gb.d08.s18`, vector `AV-GB-D08-S18-01`, package
`IWP2-AOE-GB-D08-S18`, and scheduled wave `IW2-004`. Its component ID is
`desktop_supplied_electron_bridge_origin_projection`. This is partial offline
coverage, not specialist qualification or a live finding.

The schema version 1 model supplies Electron renderer surfaces, exact trusted
origins, an explicit `trusted_only_bridge_required` policy, privileged bridge
exposure, exact allowlist or declared absence of an origin check, and
completeness fields. Entries declare remote navigation or packaged content,
reachability, renderer or external-browser target, origin, context completeness,
and per-entry `bridge_exposed` with `bridge_exposure_complete`. Surface-level
bridge presence alone cannot yield a candidate. Only canonical ASCII HTTP(S)
tuple origins are modeled. File,
app, opaque and custom schemes, redirects, preload lifecycle, context
isolation and version-specific Electron behavior are outside this projection.

A candidate requires a declared reachable remote navigation targeting the
renderer, an exposed privileged bridge on that specific entry, an origin outside the complete trusted
list, an exact allowlist admission or declared absence of an origin check, and
an explicit trusted-only bridge requirement. All relevant completeness fields
must be true. A false trusted-only requirement, declared unreachable entry,
external-browser target, packaged content, nonprivileged bridge or exact
allowlist denial yields no candidate. Wildcard, dynamic, unknown or incomplete
policy, uncertain reachability, or incomplete entry-level bridge exposure
yield `unknown`, never a candidate. A declared entry without bridge exposure
yields no candidate.

`analyze_supplied_electron_bridge_origin` accepts a native model and its
`_bytes` variant accepts bounded ASCII JSON bytes. The verifier rederives a
report against separately supplied original premises. `from_json` verifies
internal replay from embedded source only, not source provenance. Reports
include domain-separated source and report addresses, bounds, limitations,
false verification flags, and `none` effects. A synthetic request is in
`examples/offline-electron-bridge-origin-component.json`.

A candidate is only a contradiction among supplied declarations. It does not
establish that Electron navigated, a renderer loaded, a bridge was accessible,
or a method executed. The component does not open a URL or runtime, perform
network or process activity, resolve credentials, execute payloads, authorize
action, qualify a specialist, or assert exploitability.
