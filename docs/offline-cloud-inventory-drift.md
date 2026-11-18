# Supplied cloud inventory drift

The `AOE-GA-D01-S05` partial component compares two ordered, caller-supplied
cloud inventory snapshots. It groups exact `(provider, scope_id, resource_id)`
identities and reports whether a claim is new, unchanged, changed, absent from
the later supplied snapshot, or conflicted across declared sources. A prior
conflict is not silently resolved by an absent later row. Record and source
labels are retained for review.

The model has exact fields `schema_version: 1`,
`semantics_profile: supplied-cloud-inventory-drift-v1`, and `snapshots`.
Exactly two ordered snapshots are required, each with a distinct `snapshot_id`
and at most 512 records. Every record has `record_id`, `provider` (`aws`,
`azure`, or `gcp`), `scope_id`, `resource_id`, `resource_type`, `region`, and
`source_id`. Provider resource identifiers are deliberately opaque and
compared exactly. Duplicate record IDs or source claims for the same resource
identity within one snapshot are refused. The typed report is replayed from
its embedded source model and can be independently verified against a current
model.

This is supplied-data arithmetic, not provider inventory or a completed
specialist. The snapshot sources, completeness, scope ownership, resource
existence, and deletion are not authenticated. `not_observed_in_supplied_latest`
does not establish deletion. No provider client, credential, cloud account,
network connection, target interaction, qualification, or publication runs.
The [synthetic example](../examples/offline-cloud-inventory-drift-component.json)
uses fixture-only resource labels.
