# Offline provider evidence repository conformance

This leaf harness samples the existing D013 `put_quarantined` core-ingest
protocol using explicitly supplied inert adapters. Its only environment is
`reference_simulation_nonqualifying`. There is no default backend, file store,
provider SDK, network transport, credential resolver, signing, or runtime
deployment. The caller must supply in-memory reference adapters. An environment
declaration does not sandbox arbitrary Python code or authenticate an adapter.

The approved D013 decision permits provider-neutral interfaces and conformance
contracts. It does not select repository, KMS, identity, regions, retention
periods, resources, or an operational environment. This harness does not complete
those choices or the remaining D013 implementation stages.

## API and explicit fixtures

`ProviderEvidenceRepositoryConformanceCase` holds `case_id`,
`expected_behavior`, `adapter`, an existing
`ProviderEvidenceRepositoryIngestRequest`, opaque native `bytes`, and an explicit
canonical UTC `attempted_at`. Nothing supplies a default adapter or request.

`run_provider_evidence_repository_conformance` requires explicit
`environment_class`, an existing approved recommended
`ProviderEvidenceCustodyDecisionRecord`, a tuple of cases, and `maximum_calls`.
There are at most 12 cases and 16 harness `put_quarantined` invocations. This does
not bound arbitrary code inside a caller-supplied adapter. The caller's ceiling may be smaller or
zero for negative-input fixtures. The complete potential call budget and every
ordinary input fixture are checked before the first adapter invocation. Duplicate
case IDs, unsupported environments or wrapper families, malformed native
metadata, and invalid ordinary input fail closed without invocation.

Preflight reconstructs the existing decision and request contracts, binds the
request to the supplied decision, checks the fixed repository policy and
source-bound lifecycle declarations, verifies the requested maximum-five-minute
window, requires the sample time to be in that window, and matches the exact
evidence size and SHA-256. Native integer schema and size fields and native
wrapper metadata are checked before existing normalization. These checks do not
authenticate the upstream serialized verification or prove the declared
lifecycle policy is deployed. No durable authentication lookup is performed.

The harness passes a reconstructed request, not the caller's original wrapper.
Inputs are revalidated at use and checked after the adapter returns. Reassigned
request/decision metadata and late fixture changes reject the sample. Returned
receipts require the exact existing receipt family, matching native wrapper
metadata and canonical document, the public request-bound receipt validator,
and a response time within the sampled request window. Receipt/provider/object
metadata remain unsigned provider reports. These checks are not a general
Mapping-ownership or concurrent-mutation guarantee.

## Finite behaviors

| Expected behavior | Maximum calls | Passing reference observation |
| --- | ---: | --- |
| `accepted_ingest` | 1 | Valid request-bound `accepted` receipt |
| `identical_replay` | 2 | `accepted`, then `already_exists_same_digest`, with identical returned provider and object/version bindings |
| `pre_invocation_rejection` | 0 | Invalid policy, request, window, size, or digest rejected before invocation |
| `malformed_result_rejection` | 1 | Malformed, substituted, or inconsistent receipt rejected |
| `late_mutation_rejection` | 1 | Late source/wrapper/fixture mutation rejected |
| `failed_acknowledgement` | 1 | Valid `failed` provider report, without retry |
| `rejected_acknowledgement` | 1 | Valid `rejected` provider report, without fallback |
| `lost_acknowledgement` | 1 | Adapter exception classified as ambiguous, without retry |

An identical replay is an explicit two-call test scenario, not an automatic
recovery retry. Any failure, malformed result, changed source, or lost
acknowledgement stops that scenario immediately. Later scenarios use separately
declared fixtures; they are not fallback attempts. Exception text is not copied
into reports. A failed report or exception never proves that no object was
written or that rollback completed.

A mutation caught before the second explicit replay call preserves the earlier
validated receipt prefix, reports the replay case as failed, and makes no second
call. Preserving that historical sample does not authenticate the mutated source
or make the replay complete.

The current request has no repository ID, object key, or object-version ID.
Those identifiers first occur in a provider receipt. A same-object
conflicting-content operation therefore cannot be expressed truthfully through
this request contract. The narrower negative is conflicting bytes supplied with
the same exact request: size or SHA-256 mismatch must reject before invocation.
The report states `same_object_conflict_status` as
`not_expressible_by_ingest_request`; it does not invent an object-identity rule.
Changing the object version between the two sampled replay receipts fails the
sample, but does not prove external object immutability or conditional writes.

## Reports and authority boundary

`ProviderEvidenceRepositoryConformanceReport` has an `EIC-` content address,
bounded strict canonical JSON, detached dictionary output, and a reconstructing
`from_dict` parser. Reports bind the supplied decision/request document hashes,
opaque payload SHA-256 and length, exact sample times, call counts, validated
receipt documents, observations, and derived case counts. Parsing reproduces
receipt correlation, sampled shapes, and the known invocation-to-response lower
time bound. It cannot replay the original request expiry or full source-policy
contents from a document hash alone. Parsing checks content integrity and
observation shape, not the authenticity of a caller-authored report or
independently witnessed execution.

Source documents and reports are limited to 64 KiB, depth 16, 4096 visited JSON
nodes, 8192 characters per string, and signed-64-bit native integers. Duplicate
keys, floats, nonfinite values, container/scalar subclasses, and byte/structural
overruns reject. Aggregate serialized-byte charging includes escaped strings
and repeated shared subtrees before serialization. Payload bytes are bounded by
the existing 16 MiB evidence limit and are only hashed and counted, never parsed,
rendered, classified, redacted, executed, or placed in reports.

For `accepted` and replay receipts the existing six controls still say
`provider_asserted_satisfied`: conditional create, immutable version, envelope
encryption, quarantine, retention policy, and residency policy. The conformance
report separately labels **all six `unverified`**. Hash, size, request correlation,
and a returned replay/version sample do not verify these controls, provider
identity, actual encryption, actual quarantine, residency, retention, or
conditional/immutable storage facts beyond that synthetic sample. Failed or
rejected receipts retain the existing `not_claimed` controls.

Every report is `unsigned_reference_observations`, has no custody, authority,
runtime, or qualification effect, contains no raw evidence, and explicitly says
`observed_live_acceptance: false`. A passing case count is not all-six-controls
acceptance, authenticated ingest, retained repository custody, reconciliation,
legal-hold/deletion/erasure verification, a canary result, routing eligibility,
production readiness, qualification, or evidence of a real provider operation.

## Regression inputs

Tests reuse only the public opaque `EVIDENCE` constant from
`tests/agents/test_collaboration_executor_provider_evidence_service_phase144.py`
and the checked public D013 decision record. They do not invoke that test class's
heavy mission/store or signed-credential fixture. Digest-verification references
are explicitly synthetic serialized contract material built with existing
validators and the existing request/receipt builders. They are not new
authenticated provider reports or verified custody proof. The fake adapter only
hashes/counts bytes and returns synthetic receipts or injected faults in memory.

Related contracts:

- D013 decision record
- Phase 147 core-ingest contracts
- [Core-ingest implementation](../src/sunderkey/provider_evidence_repository.py)
- [Conformance regressions](../tests/agents/test_provider_evidence_repository_conformance.py)

Shared evidence, version, and navigation integration never promotes these
reference observations to custody, runtime authority, readiness, or qualification.
