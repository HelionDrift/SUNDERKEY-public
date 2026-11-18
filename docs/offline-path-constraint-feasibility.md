# Supplied Path-Constraint Feasibility

The GE-D21-S15 component enumerates a small, caller-supplied finite model of
linear integer path conditions. It accepts at most four variables with 16
sorted values each and at most 16 conditions. The 65,536-assignment ceiling
is enforced before enumeration. The report records the count of satisfying
assignments and the first deterministic witness within the supplied model.

This is not symbolic execution. No program is parsed or traced, no solver or
target is invoked, and the conditions are not verified as reachable in any
real program. Supplied completeness is an assertion. An incomplete model
remains unknown even when the enumerated subset is satisfiable or
unsatisfiable. The witness is not an exploit, finding, or authorization.

The checked synthetic example is
[`examples/offline-path-constraint-component.json`](../examples/offline-path-constraint-component.json).
Original-model replay is required for verification.
