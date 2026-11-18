# Provider evidence repository authentication integrity

This offline slice validates the serialized Phase149 ERI contract and shares its
available source-correlation checks with the existing live authentication
producer. It does not add a repository implementation or durable authentication
custody. Genuine schema1 bodies, domain separators, content-addressed identities,
boundary statuses and process-local HMAC construction are unchanged.

## Public APIs

`validate_authenticated_provider_evidence_repository_ingest_receipt_document(raw)`
accepts one exact native JSON object and returns a detached canonical object. It
replays content identities and the available embedded source relationships. It
does not construct `VerifiedPrincipal` or an authenticated ERI wrapper from JSON.

`provider_evidence_repository_ingest_authentication_effect_payload(value)` accepts
that unsigned document or an exact authenticated ERI wrapper. A wrapper must
retain its valid process-local proof and verified principal proof. The returned
detached payload contains only source identities, repository-object metadata,
content SHA and size, outcome, authentication time and explicit boundary
statuses. It performs no write or assertion consumption. Its validation status
is `unsigned_content_integrity_only`, current authority is `not_verified`, and
authority and qualification effects are `none`.

## Available source replay

Both paths check the complete eight-field EPV projection against the embedded
EPA: EPA identity and SHA, provider-report custody identity and SHA, attempt
identity, acknowledgement identity and SHA, and provider-evidence SHA. The
acknowledgement must reproduce the supplied dispatch operation, sequence,
session, credential, worker profile and fence. Mission identity, mission SHA and
scope-reference SHA must match the supplied lifecycle policy. Lifecycle and
custody-decision bindings must match the request exactly.

The retained worker and repository principals have closed serialized field sets,
native identity and SHA strings, integer policy versions and canonical UTC
timestamps. Their operations and operation-intent hashes must reproduce the
available dispatch/acknowledgement and five-field repository receipt selection.
Their authentication times must match their records, and their serialized expiry
must follow their authentication time. Repository and worker mission, store and
audience contexts must agree.

The available chronology is replayed: dispatch issuance, preparation,
acknowledgement, report receipt, source authentication, EPV verification, ingest
request, repository receipt and repository authentication. Source authentication
cannot exceed dispatch expiry. Lifecycle creation cannot follow the request, and
repository authentication must remain inside the ingest window.

## Bounded input

Public serialized input and captured source snapshots are charged before source
replay or content hashing. The canonical ASCII JSON bound is 1 MiB, with a
maximum depth of 32, 32,768 visited nodes, native strings of at most 8,192
characters and signed 64-bit native integers. Repeated references to shared
subtrees are charged each time, including JSON escaping and punctuation, before
serialization. Floating-point values, primitive/container subclasses, aliased
keys, integer booleans, missing or extra contract fields and oversized graphs
are rejected. Typed source wrappers are recaptured and revalidated at use;
their stored JSON must be canonical, bounded and free of duplicate keys or
floating-point values.

The existing authentication producer still uses the caller's verified trust
policy, verified scope grant, externally signed repository assertion and current
clock through the existing Ed25519 verification path. Native source correlation
failures are rejected before that path. This is not an arbitrary Python mapping,
concurrency or malicious trusted-client ownership boundary.

## Non-authority limits

Serialized ERI hashes demonstrate only content consistency and available source
joins. JSON alone cannot authenticate signatures, reconstruct the original
preparation body, prove source assertion issuance or `not_before`, prove scope
duration, establish current trust or revocation state, or grant access authority.
The original signed assertion, scope and trust-policy bodies are not embedded in
ERI JSON. Original opaque authentication proofs are not recreated by parsing.

The metadata does not prove that a repository object exists or that retention,
encryption, quarantine, residency, immutability or conditional-write controls
were independently satisfied. The existing statuses remain
`provider_assertions_not_independently_verified`, `prepared_policy_bound_not_activated`
and `provider_report_only`. No raw evidence, credential, provider operation,
retry, lifecycle transition, erasure, durable reconciliation, accepted custody,
runtime authority or qualification is added. Later evidence integration cannot
promote those boundaries merely by binding these files or payloads.

The regressions reuse existing synthetic Phase149 fixtures and temporary test
stores. They cover coherently rehashed source contradictions, principal intent
and time contradictions, wrapper mutation, native-type aliases, early aggregate
cost rejection, detached outputs, preserved genuine bodies and failed outcomes
that authenticate provenance only.

The separate [schema-39 metadata service](provider-evidence-repository-durable-metadata-offline.md)
adds atomic local assertion/use/effect/source custody and historical retrieval.
It does not change the unsigned validator's authority boundary or make JSON a
live principal. The original process-local seal is not reconstructed on restart.
