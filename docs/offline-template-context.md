# Supplied template context and escaping

This R0 partial component belongs to existing specialist `AOE-GB-D05-S09`,
capability `army.gb.d05.s09`, and vector `AV-GB-D05-S09-01`. It provides
partial offline algorithm evidence only, not a complete specialist,
assembled candidate, qualification, routing, or live-use approval.

## Finite declared-context projection

`analyze_supplied_template_context(model)` accepts exact version 1 data with
source labels, an engine autoescape declaration, rendering slots, and
bindings. Slot contexts are `html_text`, `html_attribute`, or `script_string`.
A binding declares origin as `trusted`, `untrusted`, or `unknown`, and explicit
escape as one of those contexts, `none`, or `opaque`. Engine autoescape is
`off`, `contextual`, or `unknown`. IDs are opaque. The model accepts no
template text, syntax, value, expression, code, or payload.

For a supplied untrusted binding, a matching explicit escape produces
`declared_matching_escape_unverified`. With no explicit escape, declared
contextual autoescape produces `declared_engine_autoescape_unverified`, while
unknown autoescape produces an unknown outcome. Opaque escaping stays unknown.
With autoescape off, no escape or a mismatching explicit escape produces a
candidate declaration gap. A mismatching explicit escape under contextual
autoescape is unknown, since the engine might transform it. Trusted origin is
only a caller declaration, not proof of safety. Missing bindings and unknown
origins remain unknown. Duplicate or conflicting identities, unsupported
semantics, missing provenance, and over-budget models are rejected.

None of these dispositions proves effective escaping or an actual weakness.
The analyzer does not parse a real template, evaluate a value, model a
specific engine, or observe browser or server behavior.

## Replay and effects

The deterministic report retains the supplied model, SHA-256 address,
source labels, slot projections, and uncertainty. `TemplateContextReport.from_json`
replays the retained model but cannot establish that it was the original
source. Consumers must call
`verify_supplied_template_context(report, model=original_model)` with the
independently held original model. The checked synthetic R0 envelope is
`examples/offline-template-context-component.json`.

The analyzer does not read a template or file, call a network endpoint,
execute rendering code, start a process, resolve credentials, generate a
payload, publish a finding, qualify a candidate, or grant target authority.
