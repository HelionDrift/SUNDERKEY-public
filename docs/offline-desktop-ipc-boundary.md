# Supplied Desktop IPC Boundary Projection

The GB-D08-S13 partial component accepts a bounded, caller-declared synthetic
graph with at most 32 process-role nodes and 64 directed IPC edges. A
deterministic breadth-first search projects paths from declared nonprivileged
entry nodes to declared privileged nodes through edges that the supplied model
marks unguarded. Declared guarded edges stop this abstract traversal. The
report contains node IDs and projected paths, not executable IPC operations.
Separate verification replays the original model.

Nodes, edges, guards, privilege labels, and graph completeness are unverified
assertions. A projected path is not a vulnerability finding, and a declared
guard is not evidence of effective enforcement. The component does not inspect
an application, start a process, exercise IPC, cross a privilege boundary,
contact a target, grant authority, or qualify a specialist.

The checked synthetic example is
[`examples/offline-desktop-ipc-component.json`](../examples/offline-desktop-ipc-component.json).
