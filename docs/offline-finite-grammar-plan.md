# Supplied Finite Grammar Plan

The GE-D21-S14 component counts derivations and minimum and maximum expansion
lengths for a bounded, caller-supplied finite grammar. It accepts at most 32
rules with 16 alternatives and eight tokens per alternative. References must
resolve and the entire rule set must be acyclic. Literal tokens are restricted
to short inert ASCII. The component does not materialize any expansion or
send bytes to a target.

The report is a local planning projection. Supplied grammar completeness is
not independently established, and unreachable rules are reported as
uncertainty. Derivation counts do not establish protocol validity, fuzzing
coverage, a vulnerability, or qualification. Every effect field is `none`.
Replay requires the original supplied model, not a report in isolation.

The checked synthetic example is
[`examples/offline-finite-grammar-component.json`](../examples/offline-finite-grammar-component.json).
