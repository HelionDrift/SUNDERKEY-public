# Supplied Container Boundary Path Declarations

The `AOE-GC-D15-S10` partial specialist compares caller-supplied path claims with caller-supplied boundary labels, exposure prerequisites, and containment-control states. It is an offline consistency projection, not a container or sandbox escape test. It contributes partial offline evidence only.

The registered bindings are capability `army.gc.d15.s10`, vector `AV-GC-D15-S10-01`, implementation package `IWP2-AOE-GC-D15-S10`, wave `IW2-012`, commander `AOE-GC-D15-CMD`, and independent validator `AOE-HQ-19`. The candidate blueprint digest is `sha256:994b086fad914ce080cd6527a0c2d1d2f8d88651e38eecb986cb7767a0931224`.

## Supplied Model

An exact native JSON object declares a source ID, an inventory-complete Boolean, at most 64 nodes, at most 128 directed edges, and at most 64 paths. Node labels are `workload`, `container_boundary`, `sandbox_boundary`, and `target_platform`. A path must start at a workload label, follow one to 16 known directed edges, cross at least one declared boundary label, and end at a target-platform label. Edge fields are abstract states only: `exposure_state` is `declared_present`, `declared_absent`, or `unknown`; `prerequisite_state` is `declared_met`, `declared_unmet`, or `unknown`; `containment_state` is `declared_effective`, `declared_ineffective`, or `unknown`.

For a complete inventory and path context with no unknown edge state, the projection computes `true` only when every edge has declared exposure, a declared met prerequisite, and declared ineffective containment. It compares that Boolean with `claimed_reaches_platform`. A disagreement is a candidate *supplied-boundary mismatch*, never evidence of platform access. Any incomplete premise produces `unknown` with no candidate. Disconnected, duplicate, over-budget, or unsupported declarations are rejected.

## Boundaries and Replay

The model is limited to 65,536 canonical bytes and the report to 131,072 bytes. Native JSON tree, string, identifier, list, and path-length bounds apply. The report carries a copy and digest of its supplied premises, but does not authenticate them. Separate original-model replay is required to verify a report or exported report bytes. The [synthetic example](../examples/offline-container-boundary-path-declarations-component.json) uses fictitious labels.

No actual exposure, prerequisite, control enforcement, platform access, or escape is verified. The component does not receive credentials, contact a target, invoke a process, publish a finding, grant positive use, or qualify a specialist. Every operational effect is `none`.
