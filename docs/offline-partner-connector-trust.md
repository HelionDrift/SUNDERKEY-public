# Supplied partner connector trust projection

This R0 component belongs to profile `AOE-GB-D06-S16`, capability
`army.gb.d06.s16`, vector `AV-GB-D06-S16-01`, package
`IWP2-AOE-GB-D06-S16`, and wave `IW2-007`. Its component ID is
`api_supplied_partner_connector_trust_projection`. It contributes partial
A7.4 evidence only and does not complete or qualify the specialist.

The schema version 1 model supplies finite partner API, B2B exchange or
low-code connector declarations. Each connector names its bound identity,
partner, allowed operation scopes, allowed data classes, enabled status and
policy completeness. Each synthetic outbound transfer names its presented
identity, destination partner, required scope, data class, context completeness
and supplied outcome. Names are literal and case-sensitive; wildcard scope
patterns are unsupported.

When all premises are complete and the connector is enabled, exact identity,
partner, scope and data-class rules produce an expected allow or deny. A
supplied allowed outcome contradicting an expected deny is a candidate
declaration mismatch. An expected allow paired with supplied denial is an
availability mismatch, not a security-bypass candidate. A matching row is
only a supplied-data match, not proof of connector enforcement. Disabled
connectors, unknown/inbound direction, incomplete policy or observation, and
unknown transfer context produce `unknown`.

`analyze_supplied_partner_connector_trust` accepts a native model;
`analyze_supplied_partner_connector_trust_bytes` accepts bounded ASCII JSON
bytes. `verify_supplied_partner_connector_trust_analysis` rederives a report
against a separately supplied original model. `from_json` validates internal
derivation from the report's embedded source, but it alone cannot establish
that the embedded source is the separately approved original. Reports include
the source model, domain-separated source and report addresses, bounds,
limitations, false verification flags and `none` effects. The synthetic R0
request is `examples/offline-partner-connector-trust-component.json`.

This leaf does not model delegation, token exchange, transformation, fan-out,
inbound flows, real data classification or actual destination enforcement. It
makes no partner, low-code runtime, credential, network, process or target call.
It does not claim observed transfer, exfiltration, live exploitability,
authority, qualification or positive use.
