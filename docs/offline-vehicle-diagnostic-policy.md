# Offline Vehicle Diagnostic Policy Projection

This R0 component supplies a narrow, metadata-only part of `AOE-GD-D25-S02`.
It compares caller-supplied diagnostic declarations with a caller-supplied local
policy. The policy lists actor roles, session labels, target IDs, service
classes, and required control labels. The `can`, `uds`, and `doip` context tags
are inert labels only. No protocol structure, service identifier, diagnostic
payload, addressing scheme, or vehicle command is accepted by the model.

The `observation` and `state_change` service classes are local policy labels,
not claims about any actual diagnostic service's effect. `approved_scope` is a
required declared control for this model, not a verified authorization. Other
controls are explicit local choices. A policy match means only that the
supplied fields pass the supplied rule. It is not permission to test or operate
on a vehicle, evidence of safety, or validation against a protocol standard.

The report is unsigned and nonqualifying. It identifies expectation mismatches
for review, while an incomplete inventory produces `unknown` with unset row
checks, unset policy matches, and no mismatch entries. Original-model
replay is required to verify an exported report. No CAN bus, DoIP endpoint,
vehicle, diagnostic tool, network, credential, or control system is contacted.
No frames or messages are generated, and no actual service effects are
inferred. The component grants no finding, approval, or execution authority.

Example: [`examples/offline-vehicle-diagnostic-policy-component.json`](../examples/offline-vehicle-diagnostic-policy-component.json).
