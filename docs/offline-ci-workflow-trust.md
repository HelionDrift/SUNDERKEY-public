# Supplied CI workflow trust-flow projection

This R0 component belongs to profile `AOE-GC-D17-S02`, capability
`supply-chain.ci-runner-workflow`, vector `AV-GC-D17-S02-01`, package
`IWP2-AOE-GC-D17-S02`, and wave `IW2-014`. It contributes partial A7.4
evidence only. It does not complete or qualify the specialist.

The schema version 1 model supplies one workflow ID, an event with declared
trust, jobs with normalized `read`, `write`, or `unknown` permissions, artifacts
with declared trust and optional producing jobs, exact `source_ids`, and a
`graph_complete` declaration. Job fields distinguish `uses_event_input`,
`uses_job_output_ids`, and `consumes_artifact_ids` from `needs_job_ids`.
Only the first three are data-flow links. `needs_job_ids` records scheduling
dependencies and does not by itself imply data transfer.

For each selected event or artifact source, the analysis finds finite,
deterministic shortest witnesses to reachable write-capable jobs. A witness
contains typed node IDs and the declared edge channels. A candidate path is
only a path through the supplied graph. Unknown source trust or target
permissions on a reachable path to a potential write job, or an incomplete
graph, prevents a negative conclusion. A complete supplied graph with no
candidate path supports only a negative
under that declared model, not a statement about a real CI provider.

`analyze_supplied_ci_workflow_trust` accepts a native model;
`analyze_supplied_ci_workflow_trust_bytes` accepts bounded ASCII JSON bytes.
`verify_supplied_ci_workflow_trust_analysis` rederives a report against a
separately supplied original model. Reports carry the exact source model,
domain-separated source and analysis addresses, bounds, limitations, false
verification flags, and `none` effects. The checked synthetic component
request is `examples/offline-ci-workflow-trust-component.json`.

This leaf does not parse live workflow YAML or expressions, execute jobs,
download artifacts, read credentials, contact CI, or claim exploitability or
actual write effects. It grants no target, authority, credential, network,
process, qualification, or positive-use permission.
