# Offline Container Runtime Declarations

This R0 partial component for `AOE-GC-D15-S02` compares caller-supplied Docker
or Podman runtime declarations with caller-supplied local requirements. It
compares engine labels and declared rootless, user-namespace and remote-API
settings. A known disagreement with `claimed_compliant` becomes an unsigned
review candidate. An absent runtime is treated as absent only when the runtime
inventory is explicitly complete. Incomplete inventory or check context
produces `unknown_supplied_context`, even when some supplied fields disagree.

The requirements are local policy conventions. The component does not inspect
daemon configuration, a running process, socket, container, image or network.
It does not prove the effective isolation or exposure of any runtime. Source
IDs, declarations and completeness flags are caller assertions, not
authenticated evidence.

The closed native JSON model accepts at most 64 runtimes and 128 checks. Its
deterministic report can be verified only by replaying a separately retained
original model. Every operational effect is `none`; the report is not a
finding, qualified specialist or approval for positive use. Registry binding:
`IWP2-AOE-GC-D15-S02`, wave `IW2-004`, commander `AOE-GC-D15-CMD`, group owner
`AOE-HQ-05`, independent validator `AOE-HQ-19`.

Example: [`examples/offline-container-runtime-declarations-component.json`](../examples/offline-container-runtime-declarations-component.json).
