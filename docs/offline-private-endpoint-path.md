# Offline Private Endpoint Path

This R0 component supports a narrow part of `AOE-GC-D14-S12`. It compares caller-supplied private-only intent with declared DNS target and route scopes. A public scope label under a private-only requirement produces a review candidate only when both scopes and context are complete. Unknown scope remains unknown.

The component does not query DNS, inspect cloud routes, send packets or establish reachability. All scope labels and policy requirements are unauthenticated caller declarations. A mismatch does not prove public exposure or unauthorized access.

The unsigned report requires separately retained original-model replay and grants no finding, qualification or positive-use authority.

Example: [`examples/offline-private-endpoint-path-component.json`](../examples/offline-private-endpoint-path-component.json).
