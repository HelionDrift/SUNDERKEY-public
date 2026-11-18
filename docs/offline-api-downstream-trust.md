# Supplied API downstream trust flow

This R0 partial component belongs to existing specialist `AOE-GB-D06-S15`,
capability `army.gb.d06.s15`, vector `AV-GB-D06-S15-01`, package
`IWP2-AOE-GB-D06-S15`, and wave `IW2-006`. It contributes partial A7.4
offline evidence only, not specialist completion, qualification, or approval
for live use.

## Finite supplied graph

`analyze_supplied_api_downstream_trust(model)` accepts exact native schema
version 1 with a declared `graph_complete` flag and separately identified
producer and flow sources. The producer lists response field IDs and caller-
declared `trusted` or `untrusted` labels. The flow contains bounded steps,
sinks, and directed edges. Supported steps are identity transforms,
validations with explicit protected sink kinds, and opaque transforms. The
supported sensitive sink kinds are command arguments, HTML rendering, SQL
queries, and URL fetches; telemetry is not treated as a sensitive sink in this
narrow model. Field IDs, step IDs, and sink IDs are exact opaque identifiers.
No response values or payloads are supplied or generated.

For a complete acyclic graph, a `candidate_path` requires a supplied
untrusted producer field to reach a sensitive sink through supported steps
without an applicable declared validation on that path. The report retains a
deterministic field-to-sink path. A separate clear path remains a candidate
even if another branch has a declared validation or opaque transform.
Validation is only a caller declaration: an applicable validation produces
`declared_protection_unverified`, not a safe or effective-sanitization verdict.

Incomplete graphs, reachable opaque-transform paths, and cyclic graphs yield
unknown dispositions rather than a candidate from those paths. Unsupported
node kinds, invalid references, duplicate identities or edges, and over-budget
models are rejected. A complete supported graph with no reachable sensitive
sink is a narrow negative result for this supplied model, not proof about any
live integration.

## Replay and effects

The deterministic report retains the supplied model, source IDs and SHA-256
addresses, candidate paths, unknowns, and uncertainty.
`verify_supplied_api_downstream_trust` rederives it against a separately
supplied original model. The checked synthetic common R0 envelope is
`examples/offline-api-downstream-trust-component.json`.

The analyzer does not call an API, fetch a URL, execute a sink, generate a
payload, start a process, resolve credentials, or interact with a target.
Candidate paths are supplied-graph observations, not a live vulnerability,
exploitability, or impact claim.
