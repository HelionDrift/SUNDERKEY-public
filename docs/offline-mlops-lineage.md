# Supplied MLOps Release Lineage

This R0 partial component belongs to `AOE-GD-D20-S01`, capability
`army.gd.d20.s01`, vector `AV-GD-D20-S01-01`, work package
`IWP2-AOE-GD-D20-S01`, and wave `IW2-006`. Its commander is
`AOE-GD-D20-CMD`, and its independent validator reference is `AOE-HQ-35`.
It is not a complete candidate, qualified specialist, or live assessment.

The version 1 model contains a bounded, ordered graph of caller-supplied
dataset, training, evaluation, and packaging stages. Each stage declares
an input and output digest, an earlier predecessor, and an approval label.
For each declared release, the algorithm walks backward to a root stage,
checks that each predecessor output equals its successor input, and records
denied approvals. Unknown approval or incomplete release context remains
unknown. A digest discontinuity or denied stage in a complete path is a
candidate declared lineage conflict.

The graph structure prevents cycles by requiring every predecessor to
appear earlier. It does not prove that a pipeline stage ran, that a digest
belongs to an actual artifact, that approvals are authentic, or that a
release was deployed. A continuous path is not a production-safety claim.

`analyze_supplied_mlops_lineage` creates an unsigned report that binds
the original model by digest without re-emitting its stage declarations.
Verification requires a separately retained original model through
`verify_supplied_mlops_lineage` or its bounded JSON-byte variant. The
checked synthetic envelope is `examples/offline-mlops-lineage-component.json`.

No dataset, model, provider, credential, file, network, pipeline runtime,
or target is accessed. The result grants no authority, finding, routing,
candidate assembly, or qualification.
