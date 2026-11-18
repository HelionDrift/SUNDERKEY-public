# Supplied API content-type differential

This R0 partial component serves existing specialist `AOE-GB-D06-S12`,
capability `army.gb.d06.s12`, vector `AV-GB-D06-S12-01`, and wave `IW2-016`.
It compares separately supplied JSON and form representations against a
caller-declared flat field schema. It does not send either representation to
a server or infer a live parser differential, bypass, or finding.

## Closed input and conclusions

`analyze_supplied_content_type_differential(model)` accepts exact native
schema version 1, a model source ID, one JSON request source, one
form-urlencoded request source, a declared field schema, and either no
responses or a supplied JSON/form response pair. Representations have exact
source IDs, content types, and bounded body text. JSON duplicate keys, malformed
percent encoding, unsupported content types, unbounded fields, depths and
nodes, and open model fields are rejected. The declared schema lists bounded
field names, types, and required flags; it is not authenticated service
documentation.

The report retains field presence, type, array element-type and form occurrence
shapes. It records representation presence or type differences, repeated form
keys, missing required fields, and disagreements with declarations. Form wire
values are strings; the analyzer does not silently coerce them to booleans,
integers, arrays, or server-side objects. The raw request and response body
values are not retained in the report. Source IDs and digests, differences,
limitations, and no-effect flags remain available for review.

`verify_supplied_content_type_differential` rederives the report against the
separately supplied original model. The common component verifier also checks
the current catalog and original request. The checked synthetic example is
`examples/offline-content-type-differential-component.json`. No provider,
network, process, credential, target, qualification, or positive-use effect is
created.
