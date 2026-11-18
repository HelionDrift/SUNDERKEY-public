# Supplied repository reference graph

The `AOE-GA-D01-S07` partial specialist projects a bounded repository link
graph from caller-supplied metadata. It compares declared owner labels for
source and target repositories, retains declared target visibility, and
distinguishes a syntactic commit digest from a named branch or tag reference.
An unsupplied target remains `unresolved_supplied_target` rather than being
treated as absent in the real world.

The model has exact fields `schema_version: 1`,
`semantics_profile: supplied-repository-reference-graph-v1`, `repositories`,
and `references`. It accepts one to 256 repository declarations and one to
512 references. Each repository has a unique `repo_id`, caller-declared
`owner_id`, `visibility`, and `source_id`. Each reference has a unique
`reference_id`, supplied source and target IDs, `selector_kind` (`commit`,
`branch`, or `tag`), `selector`, and `source_id`. Commit selectors are only
checked for lowercase 40- or 64-character hexadecimal syntax. Duplicate
references from one source are refused. The typed report replays its source
model and can be independently verified against current input.

The source metadata is unauthenticated. Owner labels and visibility are not
verified, a syntactic digest does not prove object existence or active pinning,
and named refs are not resolved. This partial component does not prove a
vulnerability, repository exposure, or target scope. No clone, repository
write, provider call, credential use, target interaction, qualification, or
publication occurs. The
[synthetic example](../examples/offline-repository-reference-component.json)
contains only fixture repository IDs and a synthetic digest.
