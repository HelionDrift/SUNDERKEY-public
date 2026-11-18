# Supplied Model Artifact Integrity

This R0 partial component belongs to `AOE-GD-D20-S08`, capability
`army.gd.d20.s08`, vector `AV-GD-D20-S08-01`, work package
`IWP2-AOE-GD-D20-S08`, and wave `IW2-003`. The commander is
`AOE-GD-D20-CMD`, and the independent validator reference is `AOE-HQ-35`.
It is not a complete candidate, qualified specialist, or live assessment.

The bounded version 1 model contains caller-supplied model artifact bytes,
expected SHA-256 digests, and origin labels. It computes each digest over
the supplied decoded bytes, then compares it with the declared expectation.
A mismatch is a local integrity candidate. A declared unapproved origin
is a separate candidate when bytes match the expectation. Unknown expected
digests and origins remain unknown. None of these declarations proves that
a model hub published, served, signed, or approved the artifact.

The synthetic fixture deliberately includes a pickle byte stream whose
digest matches its supplied expectation. The separate unsafe-serialization
specialist still flags its `GLOBAL` opcode. Digest equality and opcode
safety are independent checks, and neither result authorizes loading.

`analyze_supplied_model_artifact_integrity` creates an unsigned report.
Verification requires a separately retained original model through
`verify_supplied_model_artifact_integrity` or its bounded JSON-byte variant.
The report binds the source model by digest without re-emitting its bytes.
The checked synthetic envelope is
`examples/offline-model-artifact-integrity-component.json`.

No model is loaded, no provider or model hub is contacted, and no target,
credential, file, or network is accessed. The result grants no authority,
finding, routing, candidate assembly, or qualification.
