# Supplied Integer-Width Arithmetic

The GE-D21-S12 component calculates exact mathematical and modular results
for bounded, caller-supplied addition, subtraction, and multiplication under
declared 8, 16, or 32-bit signed or unsigned widths, or signed 64-bit width.
Unsigned 64-bit values are outside the shared signed-64 JSON integer boundary.
It checks whether a
supplied observed result equals the modular result. Inputs and observations
must fit the declared width.

This is arithmetic over a supplied model, not a program analysis. The
component does not inspect code, execute a process, verify an observation,
or model language-specific undefined behavior or compiler decisions. A width
overflow or supplied mismatch is not itself a vulnerability or finding.
Incomplete inventories remain unknown. No candidate, qualification, or
action authority is created.

The checked synthetic example is
[`examples/offline-integer-width-component.json`](../examples/offline-integer-width-component.json).
Verification requires replay against the original supplied model.
