# Supplied browser message boundary projection

This R0 component belongs to profile `AOE-GB-D05-S15`, capability
`army.gb.d05.s15`, vector `AV-GB-D05-S15-01`, package
`IWP2-AOE-GB-D05-S15`, and wave `IW2-015`. Its component ID is
`browser_supplied_message_boundary_projection`. It contributes partial A7.4
evidence only and does not complete or qualify the specialist.

The schema version 1 model supplies listener origins, declared origin-check
rules, exact accepted-origin lists, handler sensitivity and completeness. Each
message supplies a sender origin, a `target_origin`, declared payload trust and
context completeness. Only canonical ASCII HTTP(S) tuple origins are accepted.
The target may also be `*` or `unknown`; a sender may also be the opaque `null`
origin. Default ports must be omitted. IPv6, IDNA, path-bearing URLs, suffix
patterns and regular-expression rules are deliberately outside this model.

An `exact_allowlist` rule uses literal serialized-origin equality, never
prefix, suffix or substring matching. The `none` rule represents a declared
absence of an origin check. A candidate requires complete declarations, a
deliverable target, a distinct canonical sender origin, declared untrusted
payload, a sensitive handler and `none` as the origin rule. A target mismatch
does not deliver under this supplied model. Same-origin messages and messages
to nonsensitive handlers do not become candidates. Opaque origins, unknown
target or payload, incomplete declarations and unknown rule semantics yield
`unknown`, not a candidate.

`analyze_supplied_browser_message_boundary` accepts a native model;
`analyze_supplied_browser_message_boundary_bytes` accepts bounded ASCII JSON
bytes. `verify_supplied_browser_message_boundary_analysis` rederives a report
against a separately supplied original model. `from_json` validates internal
derivation from the report's embedded source, but it alone cannot establish
that the embedded source is the separately approved original. Reports contain
the source model, domain-separated source and report addresses, bounds,
limitations, false verification flags and `none` effects. The synthetic R0
request is `examples/offline-browser-message-boundary-component.json`.

This is a declaration-level postMessage projection. It does not validate data
handling or side effects and does not model CSRF or clickjacking. It generates
no payload, executes no JavaScript, opens no browser, and contacts no URL,
target, network, process or credential source. It does not claim observed
message delivery, live exploitability, authority, qualification or positive
use.
