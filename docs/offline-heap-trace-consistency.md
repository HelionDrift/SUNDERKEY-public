# Supplied Heap-Trace Consistency

The GE-D21-S09 component checks a bounded, caller-supplied sequence of
allocation, free, and access events. It identifies overlapping live address
ranges, accesses outside a declared allocation, access after a supplied free,
duplicate frees, and references to unknown allocation IDs. Allocation IDs
cannot be reused in this partial model.

No allocator, binary, process, or target is run. Event order, addresses,
sizes, IDs, and trace completeness are supplied assertions. Reported
anomalies are model inconsistencies, not verified use-after-free behavior,
memory corruption, or vulnerabilities. The component does not model
allocator reuse, aliases, concurrency, or platform memory semantics and
creates no candidate, finding, qualification, or action authority.

The checked synthetic example is
[`examples/offline-heap-trace-component.json`](../examples/offline-heap-trace-component.json).
Verification requires original-model replay.
