# Supplied Coverage Seed Selection

The GE-D21-S13 component ranks a bounded set of supplied seed coverage
bitmaps against a supplied baseline. It uses greedy marginal coverage per
asserted cost unit, with deterministic tie handling. It retains zero-gain seed
identifiers and incomplete-inventory uncertainty. No seed bytes are opened,
no target or instrumentation is run, and no crash is verified. The order is a
local corpus-planning aid, not evidence of fuzzing effectiveness or a finding.

The model accepts whole-byte bitmaps up to 2,048 bits, represented as exact
lowercase hex, and up to 32 unique seeds. A bitmap position has meaning only
within the caller's asserted coverage map. Costs are bounded positive units,
not elapsed time or provider billing. The report includes coverage counts,
selection order, source digest, and false effect flags. It is unsigned and
requires replay against the original supplied model.

The checked synthetic example is
[`examples/offline-coverage-seed-selection-component.json`](../examples/offline-coverage-seed-selection-component.json).
Only inert metadata is accepted. This component does not dispatch a fuzzer or
authorize a later target action.
