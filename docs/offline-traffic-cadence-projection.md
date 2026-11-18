# Supplied Traffic Cadence Projection

The GC-D13-S18 partial component accepts two synthetic series of four through
64 asserted, aligned, equal-duration bucket counts, each count at most 1,000.
It computes a zero-lag Pearson-style absolute correlation score in integer
basis points and compares it with a caller-declared threshold. Zero-variance
series yield an unknown result. Raw bucket counts are not repeated in the
report. Separate verification replays the original model.

Bucket alignment, counts, threshold, and completeness are unverified
assertions. Correlation is not causation and does not establish a covert
channel, tunnel, exfiltration, or security finding. The component does not
capture or send traffic, inspect payloads, access a network or target, grant
authority, or qualify a specialist.

The checked synthetic example is
[`examples/offline-traffic-cadence-component.json`](../examples/offline-traffic-cadence-component.json).
