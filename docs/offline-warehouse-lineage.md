# Supplied warehouse and lake lineage

The `AOE-GB-D07-S09` partial specialist traces caller-declared dataset
transfers backward from a requested output. It compares supplied tenant and
region tags with the objective's expected tags. It selects a shortest
declaration path to a mismatched source, if one exists. A path made only of
`declared_included` transfers receives a declared mismatch label. A path that
requires an `unknown` transfer remains unknown. `declared_excluded` transfers
do not contribute a path.

The exact native JSON model declares `schema_version: 1`,
`semantics_profile: supplied-warehouse-lineage-v1`, a lineage-completeness
boolean, up to 128 datasets, 512 transfers, and 16 objectives. Dataset,
tenant, and region identities are opaque digest references. Transfer states
are limited to `declared_included`, `declared_excluded`, and `unknown`.
Repeated or contradictory source-output transfers are refused. Input size,
structure, traversal, and report size are bounded. The typed report replays
against the original model and rejects changed input.

All tags, transfers, and completeness claims are unauthenticated. A declared
lineage mismatch is not proof of a data copy, cross-tenant exposure, a
residency violation, or a platform defect. This projection does not model
query or storage semantics, row policy, effective grants, actual partition
contents, or transport. It contacts no warehouse, lake, provider, credential,
network, or target, and grants no action authority or qualification. The
[synthetic example](../examples/offline-warehouse-lineage-component.json)
uses only fictitious opaque references.
