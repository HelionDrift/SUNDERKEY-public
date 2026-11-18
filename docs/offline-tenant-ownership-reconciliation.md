# Supplied tenant ownership reconciliation

The `AOE-GB-D09-S06` partial specialist joins caller-supplied tenant,
principal-membership, resource-owner, and access-outcome declarations. It
marks when a declared allowed event lacks a membership in the resource's
declared owner tenant, or when a declared denial occurs despite such a
membership. Both are review signals. Same-tenant membership is neither
necessary nor sufficient authorization in an unknown application policy.

The exact native JSON model declares `schema_version: 1`,
`semantics_profile: supplied-tenant-ownership-reconciliation-v1`, one to 128
unique digest-shaped tenant references, up to 512 unique membership pairs,
one to 512 resources with declared owner tenants, and one to 512 access
events. Each event has a unique ID, principal and resource reference, read or
write action label, and declared allowed result. Inputs, native structure,
strings, and reports are bounded. The typed report can be replayed from the
current supplied model.

The source of each declaration, its currentness, real ownership, and
application policy are not authenticated. A mismatch does not prove observed
cross-tenant access, an authorization defect, or a legitimate denial. No
account, resource, credential, service, or target is contacted or changed.
This component grants no positive-use authority or candidate qualification.
The [synthetic example](../examples/offline-tenant-ownership-component.json)
contains only fictitious opaque references.
