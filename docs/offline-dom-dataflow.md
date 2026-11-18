# Supplied DOM data-flow projection

This R0 component belongs to profile `AOE-GB-D05-S13`, capability
`army.gb.d05.s13`, vector `AV-GB-D05-S13-01`, package
`IWP2-AOE-GB-D05-S13`, and wave `IW2-013`. Its component ID is
`dom_supplied_dataflow_projection`. It contributes partial A7.4 evidence
only and does not complete or qualify the specialist.

The schema version 1 model supplies sources with declared trust, transforms
with a kind and declared `protects_contexts`, sinks with context and sensitivity
declarations, directed edges, selected `source_ids`, and `graph_complete`.
Supported context labels are `html_markup`, `html_attribute`,
`javascript_string`, and `url_attribute`. A sanitizer or encoder is treated
as protective only when the caller explicitly names the sink context. That
label is not verification of a real sanitizer or encoder. Declared pass-through
transforms preserve protection only within this model. A later complete encoder
or sanitizer replaces earlier context coverage with its own declared coverage;
it cannot silently preserve protection for another context.

The analysis finds finite shortest witnesses through the supplied graph for
each selected source and sink. A `candidate_unprotected_path` requires a
complete graph, a declared untrusted source, a sensitive sink with supported
complete semantics, and a path without context-matching protection or unknown
transform behavior. A declared protected path is not proof of safety. An
incomplete graph, unknown source trust, unsupported sink context, or incomplete
or unsupported transform semantics yields `unknown`, not a live finding. An
independently known unprotected path remains a candidate even when another
parallel path is unknown; that uncertainty remains explicit in the report.

`analyze_supplied_dom_dataflow` accepts a native model;
`analyze_supplied_dom_dataflow_bytes` accepts bounded ASCII JSON bytes.
`verify_supplied_dom_dataflow_analysis` rederives a report against a separately
supplied original model. Reports carry the exact source model, domain-separated
source and analysis addresses, bounds, limitations, false verification flags,
and `none` effects. The synthetic R0 request is
`examples/offline-dom-dataflow-component.json`.

This leaf generates no payload, executes no JavaScript, opens no browser, and
contacts no URL, target, network, process, or credential source. It does not
claim live XSS, exploitability, qualification, authority, or positive use.
