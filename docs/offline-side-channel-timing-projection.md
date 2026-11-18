# Supplied Side-Channel Timing Projection

The GE-D22-S09 component calculates exact minimum, maximum, doubled median,
distinct-value count, and range overlap for two caller-supplied timing groups.
Each group contains two through 256 samples with bounded integer durations.
The doubled median preserves half-nanosecond arithmetic without rounding.

Group labels, sample timings, and inventory completeness are unverified
assertions. A difference in medians or nonoverlapping ranges does not establish
statistical significance, secret-dependent leakage, exploitability, or a
finding. No implementation, secret, process, device, or target is observed.

The checked synthetic example is
[`examples/offline-side-channel-timing-component.json`](../examples/offline-side-channel-timing-component.json).
Verification requires replay against the separate original model.
