# Offline Multicluster Tenant Declarations

This R0 partial component compares bounded, caller-supplied cluster and tenant
membership identifiers. It does not inspect a cluster, verify a managed-service
claim, authenticate a tenant, or establish isolation. A discrepancy is an
unsigned candidate about the supplied declarations only. This component does
not complete the Managed Kubernetes, Multicluster and Multitenancy specialist
or grant live use, qualification, or publication authority.

Ownership is profile `AOE-GC-D15-S14`, capability `army.gc.d15.s14`, vector
`AV-GC-D15-S14-01`, work package `IWP2-AOE-GC-D15-S14`, wave `IW2-016`, commander
`AOE-GC-D15-CMD`, group owner `AOE-HQ-05`, and independent validator `AOE-HQ-19`.
The bound blueprint is
`sha256:900b5d773157c6c81b48fb72401cd911300982d551f3b621642768c369cc53d1`.

## Supplied Declaration

The native model contains exactly `schema_version`, `source_id`,
`inventory_complete`, `clusters`, and `tenants`. Each cluster has a unique
`cluster_id`, a native Boolean `managed_declared`, and unique `tenant_ids`.
Each tenant has a unique `tenant_id` and unique `cluster_ids`. These are generic
identifier declarations, not Kubernetes objects or provider records. The
example is synthetic dispatcher input.

At most 64 clusters, 64 tenants, and 256 total declared memberships are
accepted. Source and report ceilings are 64 KiB and 128 KiB. The shared
declaration core also bounds JSON nodes, depth, and string lengths. Extra
fields, duplicate IDs, and non-native types are outside the closed software
subset. They are not claimed invalid for Kubernetes or a managed provider.

## Checks and Evidence Boundary

With a complete supplied inventory, cluster-to-tenant and tenant-to-cluster
memberships must agree reciprocally. A conflict yields
`candidate_supplied_membership_mismatch`. An incomplete inventory yields
`unknown` and no candidate mismatches. An empty, noncontradictory inventory
also yields `unknown`. Matching nonempty declarations yield only
`supplied_membership_consistent`, not a finding about tenant identity, access,
or isolation. The `managed_declared` flag is preserved as a claim and never
verified.

`analyze_supplied_multicluster_tenant_declarations(model)` returns a detached,
addressed `MulticlusterTenantDeclarationReport`. The corresponding `verify_`
functions for the wrapper and exported bytes reconstruct the report against a
separately supplied original model. No network, provider, cluster, filesystem,
process, credential, target, publication, or qualification effect occurs.
