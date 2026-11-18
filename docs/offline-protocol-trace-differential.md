# Supplied Protocol Trace Differential

The GC-D13-S17 partial component compares two caller-supplied parser-stage
traces for at most 64 synthetic input digests. It computes the shared stage
prefix and separates stage, outcome, and combined differences. Duplicate input
digests or case IDs, missing traces, and unsupported labels reject.

This is an inert protocol-fuzz triage projection. The input bytes, parser
implementations, trace provenance, crash signal, and target behavior are not
verified. A supplied difference is not proof of a parser defect, crash, or
exploitable condition. No packets are sent, processes run, or findings and
action authority produced.

The checked synthetic example is
[`examples/offline-protocol-trace-differential-component.json`](../examples/offline-protocol-trace-differential-component.json).
Verification requires replay against the separate original model.
