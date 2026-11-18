# Supplied Pickle Opcode Safety

This R0 partial component belongs to `AOE-GD-D20-S07`, capability
`army.gd.d20.s07`, vector `AV-GD-D20-S07-01`, work package
`IWP2-AOE-GD-D20-S07`, and wave `IW2-012`. The commander is
`AOE-GD-D20-CMD`, and the independent validator reference is `AOE-HQ-35`.
It is not a complete candidate, qualified specialist, or live assessment.

The bounded version 1 model accepts up to eight caller-supplied canonical
base64 pickle byte streams, each no more than 8,192 decoded bytes. The
algorithm delegates syntax inventory to the existing bounded pickle-opcode
component, which uses `pickletools.genops`. It never calls a
pickle loader or imports a referenced callable. Reports contain only risky
opcode names and counts derived from the supplied stream, not global
arguments, artifact bytes, or execution traces. A parse failure, missing `STOP`, trailing
bytes, or opcode limit produces an unknown disposition.

When a parsed stream has an opcode capable of invoking or constructing
objects and its supplied loader policy is `allowed`, the result is a
`candidate_risky_pickle_opcode`. This is a syntactic risk indicator, not
proof of malicious content, actual loading, target reachability, or impact.
A declared denied loader changes the disposition, but the denial is not
verified. The absence of listed opcodes does not establish safety.

`analyze_supplied_pickle_opcodes` creates an unsigned report. Verification
requires a separately retained original model through
`verify_supplied_pickle_opcodes` or its bounded JSON-byte variant. The
checked synthetic envelope is
`examples/offline-pickle-opcode-safety-component.json`.
The report binds the original model by digest and does not re-emit its bytes.

No target, file, provider, credential, or network is accessed. The result
grants no authority, finding, routing, candidate assembly, or qualification.
