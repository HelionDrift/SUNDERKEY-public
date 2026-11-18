# Offline Cloud Artifact Timeline

This R0 component supports a narrow part of `AOE-GC-D14-S18`. It compares caller-supplied baseline and later snapshot membership for role-trust, access-key metadata, and automation-binding declarations. A review candidate requires complete context and an artifact declared absent in the baseline, present later, and not covered by a declared approved change. Incomplete context produces `unknown`.

No credential material or artifact contents are accepted, and no cloud provider or target is queried. Snapshot completeness, source authenticity, approval, persistence, and compromise are not established. The unsigned report requires separately retained original-model replay and grants no finding, qualification, or positive-use authority.

Example: [`examples/offline-cloud-post-compromise-timeline-component.json`](../examples/offline-cloud-post-compromise-timeline-component.json).
