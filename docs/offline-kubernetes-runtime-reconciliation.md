# Offline Kubernetes Runtime Reconciliation

This R0 partial component compares bounded, caller-supplied desired workload
rows with caller-supplied runtime rows. It does not render Helm templates,
execute an operator or GitOps controller, query a cluster, or authenticate any
inventory. A discrepancy is an unsigned candidate about the declarations
only. It does not complete the Cluster-Runtime Consumption Through Helm,
Operators and GitOps specialist or grant live use, qualification, or
publication authority.

Ownership is profile `AOE-GC-D15-S12`, capability `army.gc.d15.s12`, vector
`AV-GC-D15-S12-01`, work package `IWP2-AOE-GC-D15-S12`, wave `IW2-014`,
commander `AOE-GC-D15-CMD`, group owner `AOE-HQ-05`, and independent validator
`AOE-HQ-19`. The bound blueprint is
`sha256:5bd4891d97762de8894be24ea392501e960d6c978ca61c76e0dc2a98c9fe18a1`.

## Supplied Declaration

The native model contains exactly `schema_version`, `source_id`,
`inventory_complete`, `desired`, and `runtime`. A desired row has `namespace`,
`workload_id`, `delivery_kind` (`helm`, `operator`, or `gitops`), `revision`,
and lowercase SHA-256 `image_digest`. A runtime row has the same namespace,
workload ID and image digest, plus a `revision` that may be null. Each list
has unique namespace and workload ID pairs. The rows are a synthetic finite
model, not Kubernetes API objects or parsed YAML. The example file is a
synthetic dispatcher input.

Each list accepts at most 64 rows. The source and report ceilings are 64 KiB
and 128 KiB. The shared declaration core also bounds JSON nodes, depth, and
string lengths. Extra fields and non-native types are rejected by this closed
software model, not declared invalid Kubernetes resources.

## Checks and Evidence Boundary

For a complete supplied inventory, rows join by exact namespace and workload
ID. The component compares supplied image digests and revisions, and identifies
missing or undeclared runtime rows. A null runtime revision remains unknown,
not a revision conflict. An incomplete inventory yields `unknown`, null match
values, and zero candidate mismatches regardless of apparent row differences.
Matching rows yield only `supplied_runtime_consistent`, not proof of deployment
state, controller reconciliation, traffic exposure, or runtime safety.

`analyze_supplied_kubernetes_runtime_reconciliation(model)` returns a
detached, addressed `KubernetesRuntimeReconciliationReport`. The corresponding
`verify_` functions for the wrapper and exported bytes reconstruct it against
a separately supplied original model. No cluster, network, filesystem,
process, provider, credential, target, publication, or qualification effect
occurs.
