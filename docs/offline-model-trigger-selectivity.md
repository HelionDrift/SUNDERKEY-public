# Supplied Model Trigger Selectivity

This R0 partial component belongs to `AOE-GD-D20-S03`, capability
`army.gd.d20.s03`, vector `AV-GD-D20-S03-01`, work package
`IWP2-AOE-GD-D20-S03`, and wave `IW2-008`. Its commander is
`AOE-GD-D20-CMD`, and its independent validator reference is `AOE-HQ-35`.
It is not a complete candidate, qualified specialist, or live assessment.

The version 1 model contains caller-supplied clean and trigger-conditioned
trial counts for a declared target label. It compares the target-label
rates with exact cross-multiplication, using a supplied minimum sample
count and rate-gap threshold in basis points. A gap strictly above the
threshold is a candidate only when both groups meet the sample minimum
and comparability and context are declared. Equality is not a candidate;
insufficient samples and missing comparability remain unknown.

The component accepts no trigger content, generates no trigger, and never
queries or modifies a model. Counts, grouping, label identity, model
version, and comparability are not authenticated. A rate gap may reflect
benign data shift or test bias. A candidate is statistical selectivity,
not proof of a backdoor, poisoning, exploitability, or impact.

`analyze_supplied_model_trigger_selectivity` creates an unsigned report
that binds its source model by digest without re-emitting it. Verification
requires a separately retained original model through
`verify_supplied_model_trigger_selectivity` or its bounded JSON-byte
variant. The checked synthetic envelope is
`examples/offline-model-trigger-selectivity-component.json`.

No provider, credential, file, network, model runtime, or target is
accessed. The result grants no authority, finding, routing, candidate
assembly, or qualification.
