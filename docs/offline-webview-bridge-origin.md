# Supplied deep-link WebView bridge-origin projection

This R0 component belongs to profile `AOE-GB-D08-S12`, capability
`army.gb.d08.s12`, vector `AV-GB-D08-S12-01`, package
`IWP2-AOE-GB-D08-S12`, and scheduled wave `IW2-016`. Its component ID is
`browser_supplied_webview_bridge_origin_projection`. This is partial offline
coverage, not specialist qualification or a live finding.

The schema version 1 model supplies WebView surfaces, exact trusted origins,
an explicit `trusted_only_bridge_required` policy, bridge exposure, an exact
allowlist or declared absence of an origin check, and completeness fields.
Entries declare external deep-link or internal-navigation origin, reachability,
target surface, context completeness, and per-entry `bridge_exposed` with
`bridge_exposure_complete`. Surface-level bridge presence alone cannot yield
a candidate. Only canonical ASCII HTTP(S) tuple
origins are accepted. Paths, redirects, custom schemes, opaque origins, IDNA,
IPv6 and browser-dependent origin rules are not modeled.

A candidate requires a declared reachable external deep link targeting the
WebView, an exposed privileged bridge on that specific entry, an origin outside the complete trusted
list, an exact allowlist admission or declared absence of an origin check, and
an explicit trusted-only bridge requirement. All relevant completeness fields
must be true. A false trusted-only requirement, declared unreachable entry,
external-browser target, internal navigation, nonprivileged bridge or exact
allowlist denial yields no candidate. Wildcard, dynamic, unknown or incomplete
policy, uncertain reachability, or incomplete entry-level bridge exposure
yield `unknown`, never a candidate. A declared entry without bridge exposure
yields no candidate.

`analyze_supplied_webview_bridge_origin` accepts a native model and its
`_bytes` variant accepts bounded ASCII JSON bytes. The verifier rederives a
report against separately supplied original premises. `from_json` verifies
internal replay from embedded source only, not source provenance. Reports
include domain-separated source and report addresses, bounds, limitations,
false verification flags, and `none` effects. A synthetic request is in
`examples/offline-webview-bridge-origin-component.json`.

A candidate is only a contradiction among supplied declarations. It does not
establish that a deep link was invoked, a page loaded, a bridge was accessible,
or a method executed. The component does not open a URL or browser, perform
network or process activity, resolve credentials, execute payloads, authorize
action, qualify a specialist, or assert exploitability.
