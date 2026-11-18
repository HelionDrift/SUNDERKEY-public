# Offline Secondary Cloud Control Declarations

This R0 component supports a narrow part of `AOE-GC-D14-S08`. It compares caller-supplied required-control flags with declared observed states for one named secondary-cloud tenant. A review candidate requires complete context and a required control declared `not_enforced`. Unknown state or incomplete context produces `unknown`, not a candidate.

The provider family is a label, not a provider-specific policy interpreter. No provider is queried, and neither effective enforcement nor exposure is established. The unsigned report requires separately retained original-model replay and grants no finding, qualification, or positive-use authority.

Example: [`examples/offline-secondary-cloud-control-declarations-component.json`](../examples/offline-secondary-cloud-control-declarations-component.json).
