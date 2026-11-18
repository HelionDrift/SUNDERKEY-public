# Supplied Hardware Trace Difference Projection

The GD-D18-S08 partial component compares two bounded groups of
caller-supplied synthetic traces for an asserted power, EM, or timing
modality. All traces must have the same sample count and contain bounded
integer samples. The analyzer computes exact per-index differences of
group means using integer numerators and a shared denominator, then
identifies the largest absolute descriptive difference. The checked
example is
[`examples/offline-hardware-trace-difference-component.json`](../examples/offline-hardware-trace-difference-component.json).

This waveform-index projection is distinct from the scalar
[side-channel timing summary](offline-side-channel-timing-projection.md).
It does not calculate statistical significance, control for confounders,
authenticate an instrument, verify alignment, or infer secret-dependent
leakage. Inventory completeness and alignment are supplied assertions;
missing either leaves the disposition unknown. No physical signal,
device, target, or secret is observed. No finding, qualification, or
action authority follows from a numeric difference.

Independent verification replays the exact original model. Duplicate
trace IDs, uneven lengths, noninteger values, and nonsynthetic input are
rejected.
