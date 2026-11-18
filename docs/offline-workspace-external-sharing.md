# Offline Workspace External Sharing

This R0 component supports a narrow part of `AOE-GC-D14-S19`. It compares active caller-supplied document grants with a declared tenant domain and per-scope external-sharing policy. A review candidate requires an active grant to a different declared domain under a policy that denies external sharing, with complete context.

The component does not query Google Workspace, inspect inherited policies, resolve groups or links, verify grant effectiveness, or access documents. Domains, roles, grants and policies are caller-supplied. A mismatch does not prove disclosure or effective access.

The unsigned report requires separately retained original-model replay and grants no finding, qualification or positive-use authority.

Example: [`examples/offline-workspace-external-sharing-component.json`](../examples/offline-workspace-external-sharing-component.json).
