# Supplied directory lifecycle projection

This R0 partial component belongs to `AOE-GA-D03-S15`, capability
`army.ga.d03.s15`, vector `AV-GA-D03-S15-01`, and wave `IW2-016`.
It compares two caller-supplied LDAP or SCIM-shaped snapshots and requested
deprovision operations. It does not query a directory, perform provisioning,
or establish that effective access was revoked.

The bounded version 1 model binds separate source IDs for before, after, and
operation records. User active flags and group membership sets are explicit.
With complete supplied snapshots, missing users still named in after-group
memberships become orphan-membership candidates; requested disable, delete,
or membership-removal operations that are not reflected in the after snapshot
become unreflected-operation candidates. Incomplete snapshots produce unknown
states instead of positive or negative conclusions. These are consistency
relations among unverified records, not server behavior or authorization
outcomes.

`analyze_supplied_scim_lifecycle` returns a source-bearing report with
embedded bounded premises. `verify_supplied_scim_lifecycle` replays against a
separately supplied original model; the common verifier also rechecks the
original request and current catalog. The synthetic example is
`examples/offline-scim-lifecycle-component.json`. No provider, target,
credential, network, execution, qualification, or routing authority is granted.
