# Supplied eBPF Helper-Policy Projection

The GC-D12-S02 partial component compares at most 64 synthetic eBPF program
declarations with caller-supplied helper allowlists by program type. It marks
declared helpers outside the supplied policy. Separate verification replays
the original supplied model.

Program types, helper IDs, policy, and completeness are unverified assertions.
No bytecode is parsed, no kernel verifier is invoked, and no program is loaded.
A mismatch does not establish exploitability, execution, or a finding. This
component grants no authority or qualification.

The checked synthetic example is
[`examples/offline-ebpf-helper-component.json`](../examples/offline-ebpf-helper-component.json).
