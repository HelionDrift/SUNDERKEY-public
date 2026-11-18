# Supplied Evasion Delta Measurement

This R0 partial component belongs to `AOE-GD-D20-S04`, capability
`army.gd.d20.s04`, vector `AV-GD-D20-S04-01`, work package
`IWP2-AOE-GD-D20-S04`, and wave `IW2-009`. Its commander is
`AOE-GD-D20-CMD`, and its independent validator reference is `AOE-HQ-35`.
It is not a complete candidate, qualified specialist, or live assessment.

The version 1 model contains caller-supplied integer baseline and candidate
vectors, label declarations, and a maximum L-infinity and squared-L2
perturbation budget. The algorithm measures absolute coordinate differences
with exact integer arithmetic. A declared label change at or below both
budgets is a candidate. A change outside either budget and an unchanged
label are separate negative dispositions. Incomplete context or a missing
evaluation declaration remains unknown.
Different declared labels for identical vectors also remain unknown rather
than being counted as evasion.

This component does not generate a candidate input, query a model, check
that declared labels came from one model version, or prove adversarial
evasion. It also does not normalize input units, infer a semantic distance,
or establish downstream impact. A candidate is only a reproducible
projection of the supplied vectors, labels, and budget.

`analyze_supplied_evasion_deltas` creates an unsigned report that binds
the original model by digest without re-emitting vectors. Verification
requires a separately retained original model through
`verify_supplied_evasion_deltas` or its bounded JSON-byte variant. The
checked synthetic envelope is
`examples/offline-evasion-delta-measurement-component.json`.

No provider, credential, file, network, model runtime, or target is
accessed. The result grants no authority, finding, routing, candidate
assembly, or qualification.
