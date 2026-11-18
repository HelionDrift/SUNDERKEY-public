# Supplied DNS Scope Timeline

The `AOE-GE-D23-S06` partial specialist classifies IP address scopes in a
caller-supplied sequence of DNS answer snapshots for one hostname. A transition
from an all-global answer set to an all-private, loopback, or link-local set is
labelled `candidate_global_to_internal_shift`. Mixed answer sets remain
`unknown_mixed_answer_shift`. These are arithmetic and address-class labels on
the supplied sequence, not observations of a resolver or application.

The exact native JSON model declares `schema_version: 1`,
`semantics_profile: supplied-dns-scope-timeline-v1`, a canonical ASCII DNS
hostname, and 2 to 64 snapshots with strictly increasing sequence numbers.
Each snapshot has 1 to 16 IP literals. Duplicate identifiers, duplicate
canonical addresses, IPv6 zone identifiers, unknown fields, and over-budget
models are refused. The typed report embeds and replays the source model;
verification against an alternate model fails.

The model does not provide resolver provenance, cache behavior, DNS timing,
request routing, URL validation, or application fetch evidence. A candidate
transition does not prove DNS rebinding or SSRF. No DNS query, URL fetch,
credential use, network call, target interaction, action authority, finding
publication, or qualification occurs. The
[synthetic example](../examples/offline-dns-scope-timeline-component.json)
contains only supplied declarations.
