# Offline Kubernetes Control Plane Declarations

This R0 partial component for `AOE-GC-D15-S06` compares caller-supplied API
server and etcd store declarations with caller-supplied local requirements.
It checks the declared API-to-store reference, client-TLS requirements and
at-rest encryption declaration. A known disagreement with
`claimed_compliant` becomes an unsigned review candidate. An absent API
server or store is treated as absent only when its respective inventory is
explicitly complete. Incomplete inventory or check context produces
`unknown_supplied_context`, even when some supplied fields disagree.

These comparisons are local policy conventions. TLS and encryption fields
are declarations, not validation of effective transport protection, key
management, encryption provider configuration or stored data. The at-rest
field is a supplied store-level control label, not a model of
Kubernetes API-server `EncryptionConfiguration` or resource-by-resource
encryption coverage. The component does not contact a Kubernetes API, etcd
endpoint, cluster or network. Source
IDs, declarations and completeness flags are caller assertions, not
authenticated evidence.

The closed native JSON model accepts at most 64 API servers, 64 stores and
128 checks. Its deterministic report can be verified only by replaying a
separately retained original model. Every operational effect is `none`; the
report is not a finding, qualified specialist or approval for positive use.
Registry binding: `IWP2-AOE-GC-D15-S06`, wave `IW2-008`, commander
`AOE-GC-D15-CMD`, group owner `AOE-HQ-05`, independent validator `AOE-HQ-19`.

Example: [`examples/offline-kubernetes-control-plane-declarations-component.json`](../examples/offline-kubernetes-control-plane-declarations-component.json).
