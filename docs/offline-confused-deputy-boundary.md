# Supplied Requester and Deputy Boundary

The `AOE-GE-D23-S14` partial specialist compares caller-declared requester
authority, deputy authority, a delegation claim, and an outcome for an inert
operation. An explicit policy can require requester authority even when the
deputy is separately authorized. When complete supplied premises say the
requester is denied, the deputy is allowed, and the outcome allows the
delegated operation, the projection reports only a
`candidate_declared_deputy_boundary_conflict`.

The model never invokes the operation or establishes what either actor can do
in a real system. Unknown authority, incomplete capture, and missing policy
premises withhold a candidate conflict. Actor and resource references are
opaque labels, not credentials or target selectors.

The source is limited to 128 operations and 32 KiB. The 64 KiB report embeds
the source for separate-source replay. No network, file, process, credential,
target, execution, publication, or qualification effect occurs. The
[synthetic example](../examples/offline-confused-deputy-boundary-component.json)
contains declared decisions only.
