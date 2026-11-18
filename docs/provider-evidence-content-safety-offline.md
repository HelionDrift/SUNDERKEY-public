# Passive evidence observations and derivative provenance

This leaf boundary implements a bounded synthetic-only part of the approved
D013 direction.
It does not classify, parse, render, execute, transform or redact evidence.
It has no provider, store, credential, callback, transport or retry interface.
The explicit environment is `reference_simulation_nonqualifying`.
That is a caller declaration, not proof that arbitrary supplied bytes are
synthetic or authorization to use live evidence.

## Supplied sources and bytes

`observe_provider_evidence_content_prefix` requires native immutable bytes,
an exact Phase147 `ProviderEvidenceRepositoryIngestRequest` and an exact
Phase148 `ProviderEvidenceLifecyclePolicy`. It revalidates canonical source
documents, native schema/counter types and wrapper identifiers and hashes.
It recomputes the source SHA-256 and length, then joins all eight lifecycle
references, the custody decision and policy-created/request chronology.

Reports retain the exact source request and policy references, policy mission
and scope hashes, evidence-verification reference, original source digest and
length, and declared verification/request/expiry/policy-creation times. The
mission is bound through the request's exact lifecycle-policy reference. This
is not independent verification of the original mission, dispatch, signed
worker report or actual source authenticity. Those full source bodies are not
inputs to this leaf.

No clock is sampled. Original times describe historical source metadata;
they do not renew an ingest window, grant current access, activate a policy or
authorize a post-expiry operation. Ordinary source requests retain their
existing five-minute window and prepared, nonactivated policy semantics.

## Finite passive prefix observations

The observer compares at most nine leading bytes with an immutable table of
eleven fixed byte features: angle-open, doctype-open, ELF, gzip, JPEG, PDF,
PNG, XML-declaration-open and three ZIP markers. Feature names describe
prefix equality, not an accepted file type or MIME classification.

The result explicitly distinguishes known, ambiguous, truncated and unknown
prefix observations. Overlapping or incomplete candidates remain visible.
For example, an XML-declaration prefix also matches angle-open and is marked
ambiguous; `PK` is a truncated candidate, not a complete ZIP assertion.
All observations keep `type_verdict=not_determined` and
`malware_safety_verdict=not_assessed`. A known prefix does not prove that the
rest of an object is valid, safe, nonmalicious or appropriate for any processor.
Caller-declared media types are not treated as observed facts.

## Supplied derivative provenance

`verify_provider_evidence_derivative_provenance` receives original and
derivative bytes separately. Its explicit declaration has three closed
sections:

- `source`: exact request ID/hash, lifecycle-policy ID/hash, policy mission
  binding, source content address and byte length;
- `derivative`: the declared derivative content address and byte length;
- `transformation`: a bounded `transformationref:` identifier, declared
  definition hash and `derived_candidate` or `redacted_candidate` claim.

Both byte sequences must be native `bytes` and between one byte and the
existing 16 MiB evidence limit. The verifier recomputes both digests and
lengths, checks the declared source against the supplied contracts and
requires a different derivative digest/address. It performs no transformation
and cannot prove that the declared definition was used. A redacted-candidate
label is not a redaction or classification result. A correct hash and provenance
link do not prove removal of secrets, malware, regulated data or hostile content.

## Unsigned replay and bounds

`ProviderEvidenceContentSafetyReport` supplies content-addressed `EPO-` or
`EDP-` metadata with detached dictionaries. Its constructors and parsers check
closed fields, native types, internal metadata consistency and the new report
hash only. They do not authenticate or verify unavailable bytes. Use
`verify_provider_evidence_content_observation_document` or
`verify_provider_evidence_derivative_provenance_document` to replay the exact
supplied bytes, source contracts and explicit declaration. A coherently
readdressed false observation still fails that replay.

Each supplied metadata or source JSON document has its own 64 KiB aggregate
serialized-byte limit, depth 16, 4096 nodes, bounded strings and signed-64-bit
integers. This is a per-document budget, not one combined budget across the
request, lifecycle policy and provenance. The existing pure visitor charges
escaping and repeated shared subtrees before serialization.
Duplicate JSON keys, floats, aliases, subclasses, oversized bytes/documents,
unsupported fields and conflicting source metadata fail closed. There is no
general arbitrary in-process code or concurrent-mutation sandbox claim.

Reports contain no raw bytes, derivative bytes or parsed content. Authentication
remains unsigned reference metadata; content safety, quarantine and transformation
success remain unverified. All declared effects, including classification,
redaction, quarantine release, activation, storage, network, target authority
and qualification, are `none`. Existing signed domains, identity operations,
accepted custody and lifecycle authority are unchanged.

The tests reuse genuine Phase147/148 synthetic fixtures. Extra prefix cases
use explicitly unsigned serialized EPV projections for fixed synthetic bytes,
not new authenticated provider reports. No operational repository or content
processor is invoked, and no input bytes are modified.
