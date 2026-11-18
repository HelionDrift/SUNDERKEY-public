# Supplied Binary Reference Graph

The GE-D21-S16 component projects entry reachability and recursive symbol
groups from a bounded, caller-supplied function-reference graph. It accepts
at most 64 named functions, 16 call references per function, and 16 entry
symbols. Every reference must resolve within the supplied inventory.

No binary bytes are opened or disassembled. Function boundaries, call edges,
entry points, and inventory completeness are supplied assertions. Reachable
symbols are graph facts, not an observed runtime call path. A graph cycle is
not proof that execution recurses. The report cannot establish a finding,
candidate, qualification, or authority to act.

The checked synthetic example is
[`examples/offline-binary-reference-component.json`](../examples/offline-binary-reference-component.json).
Verification requires original-model replay.
