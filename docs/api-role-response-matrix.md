# API role-response evidence matrix

The traffic-derived API inventory summarizes roles and HTTP status codes for
each endpoint independently. That summary does not preserve which role
produced which response. This repository-only V9.5 slice rebuilds that exact
association from the same supplied sanitized observations and binds the
result to the inventory digest.

`verify_api_role_response_matrix_from_sources` replays a stored matrix from
the supplied inventory and observations. The builder rejects observations
whose in-memory fields no longer match their content address. This replay
checks the matrix derivation, not the inventory's underlying contract or the
completeness and currentness of collection.

The matrix requires exact tenant, context, and scope revisions. It deduplicates
identical event IDs, rejects conflicting event IDs, and verifies that the
provided observations exactly cover every inventory observation and endpoint
aggregation. Each row contains an opaque role reference, canonical HTTPS
origin, method, redacted path shape, observed status codes, count, time span,
source digests, and observation digests. No headers, bodies, query values,
session tokens, or raw principal identifiers are added.

The builder verifies each supplied observation's content address against a
fresh reconstruction and uses the reconstructed record. It does not rely on
Python's frozen-object convention as a source-integrity guarantee. This catches
stale digests even when a caller changes an object's status or overrides its
body representation; it does not authenticate the producer's assertions.

The requested inventory is also reconstructed into an owned base view,
including its declared endpoint scalars and tuple contents, and checked against
the unchanged supplied digest. Both sides of binding and aggregation comparisons
therefore use underlying primitive values, not caller-defined equality or
ordering. The original observations and inventory are not modified. Tuple
subclass hooks cannot substitute the observation window or bypass its hard limit.

The [matrix-bound release review](api-release-role-response-review.md) compares
these associations across exact release windows while retaining the existing
inventory-only delta as separately bound evidence.

A response status is evidence of a response only. A `200` does not prove
authorization, and a `403` does not prove that every attempt by that role is
denied. Absent role-endpoint pairs are not tested or inaccessible claims.
The output has no authorization verdict, target authority, qualification,
network, scheduling, or execution effect. Production use still needs approved
traffic collection, authenticated provenance, coverage assessment, and
separately authorized active validation where warranted.
