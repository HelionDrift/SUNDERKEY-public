# Supplied Training Label Drift

This R0 partial component belongs to `AOE-GD-D20-S02`, capability
`army.gd.d20.s02`, vector `AV-GD-D20-S02-01`, work package
`IWP2-AOE-GD-D20-S02`, and wave `IW2-007`. Its commander is
`AOE-GD-D20-CMD`, and its independent validator reference is `AOE-HQ-35`.
It is not a complete candidate, qualified specialist, or live assessment.

The version 1 model contains caller-supplied baseline and candidate label
counts with a maximum absolute share change in basis points. For each
label in either supplied distribution, the algorithm compares shares with
exact cross-multiplication. Counts are bounded so all reported integers
remain within signed 64-bit JSON limits. A share change strictly above
the supplied ceiling is a candidate; equality is not. A missing label
in one declared complete distribution has count zero. If completeness is
not declared, all comparisons remain unknown.

Distribution drift may be legitimate. The component does not read
training records, validate sample identity or representativeness, train
a model, or establish poisoning. The counts and completeness are not
authenticated. A candidate only identifies a reproducible contradiction
with the declared distribution threshold.

`analyze_supplied_training_label_drift` creates an unsigned report that
binds the source model by digest without re-emitting it. Verification
requires a separately retained original model through
`verify_supplied_training_label_drift` or its bounded JSON-byte variant.
The checked synthetic envelope is
`examples/offline-training-label-drift-component.json`.

No provider, credential, file, network, model runtime, or target is
accessed. The result grants no authority, finding, routing, candidate
assembly, or qualification.
