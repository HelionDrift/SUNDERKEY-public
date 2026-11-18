# Offline planning preview service

The preview service exposes a bounded summary of a stored offline API planning
bundle. The caller provides a typed access context, exact bundle digest, and
expected scope digest. The service binds its authorization check to the full
request, requires the request time to match an injected trusted clock,
and checks that the storage record repeats the authorized tenant, context,
and bundle digest.

Before returning anything, it checks historical bundle integrity against the
Army registry. The result reports schedule and world digests, task counts and
types, blocked reasons, and rehearsal wave counts. It does not return raw
evidence or source response bodies. It makes no storage mutation, network
request, execution, qualification, or finding publication.

The framework-neutral ASGI adapter exposes `POST /v1/planning/previews` with
only `request_id`, `access`, `bundle_sha256`, and `expected_scope_sha256`. It
sets the request time from the server clock, applies the same bounded JSON,
header, and credential-value checks as the local service route, and never
accepts a caller-supplied timestamp. The adapter has injected storage and
authorization ports. It does not create a listener or provide production
authentication.

This preview is historical and read-only. The integrity check does not replay
the original API case sources or establish that a scope and its route remain
current. The preview explicitly reports `source_replay_performed: false` and
`positive_use_approved: false`.
