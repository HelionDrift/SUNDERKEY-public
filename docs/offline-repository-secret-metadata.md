# Supplied Repository And Build-Log Secret Metadata Review

This R0 partial component belongs to existing specialist `AOE-GC-D17-S11`,
capability `army.gc.d17.s11`, vector `AV-GC-D17-S11-01`, package
`IWP2-AOE-GC-D17-S11`, and wave `IW2-023`. It contributes only partial A7.4
offline evidence, not a qualified secret scanner, live finding or credential
response workflow.

## Metadata Boundary And Candidate Rules

`analyze_supplied_repository_secret_metadata(model)` accepts an asserted
inventory-completeness flag and at most 64 reduced occurrence rows. Each row
has an opaque occurrence ID, an independently assigned opaque incident ID,
either `repository` or `build_log`, a declared audience, and boolean redaction,
rotation and removal confirmations. The closed model has no secret value,
reusable hash, file path, log content or credential field. Operators must not
derive opaque IDs from secret bytes or place secrets inside labels. The
component cannot authenticate that input discipline.

An asserted public, unredacted occurrence is a review candidate. The same
opaque incident label on both declared surfaces is a separate co-occurrence
candidate, not proof of the same credential or propagation. Missing rotation
or removal confirmation and incomplete inventory remain uncertainty. An
absence of signals does not establish that no secret exists or that response
is complete.

## Replay And Limits

`verify_supplied_repository_secret_metadata` recomputes the content-addressed
report against a separately supplied original model. The synthetic
[example](../examples/offline-repository-secret-metadata-component.json)
contains only fixture labels. The analyzer does not scan a repository or log,
read a credential, test its validity, rotate a credential, contact a target,
publish a finding or grant positive-use authority. Audience and remediation
flags are unauthenticated operator assertions.
