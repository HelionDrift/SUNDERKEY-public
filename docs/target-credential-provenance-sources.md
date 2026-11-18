# Source-derived target credential provenance

`target_credential_provenance` is a pure metadata composition leaf. It prepares
and replays the existing version 2 `TargetCredentialProvenance` (TACP) against
supplied version 1 `CredentialDescriptor` (CBD) and `CredentialLease` (CLZ)
bodies and a supplied `TargetAuthenticationProviderBinding` (TAPB). It does not
resolve a credential, invoke a provider, open a store, issue or consume a lease,
sign an attestation, authenticate to a target, or authorize any operation.

## Explicit public API

`prepare_target_credential_provenance` takes keyword-only `descriptor`, `lease`,
`provider`, `factor`, `lease_use_number`, `transport_credential_ref`,
`mapping_attestation_sha256` and `created_at`. Source arguments are the exact
existing wrapper families. Factor is an exact `AuthenticationFactor`, use is a
native integer and the reference, digest and canonical UTC time are native
strings. There are no operational defaults, callbacks or current clock.

`verify_target_credential_provenance_sources` takes keyword-only `provenance`,
the same three sources and the explicit `transport_credential_ref`. It
independently reconstructs the expected TACP using the retained factor, use
ordinal, mapping digest and creation time, and compares its complete canonical
document with the supplied provenance. Both functions return an exact detached
existing TACP, not a new verification or authorization receipt. Invalid input
raises `TargetCredentialProvenanceSourceError`, a subclass of the existing
`TargetAuthenticationContractError`.

## Source joins and derived fields

Every source is captured, reconstructed and compared in full, including its
declared identifier and digest. Nested broker `ProviderAdapter` fields and
target-provider TAPE profiles and addresses are included. The helper does not
trust an address without replaying the supplied body or hide changed content
through constructor normalization.

The CLZ descriptor digest, tenant, assessment and subject must equal the CBD.
Its target, technique and purpose must occur in the descriptor's corresponding
allowed sets. Scopes must be a subset, mode must be allowed and lease use count
must not exceed the descriptor ceiling. The complete lease window must fit
inside the descriptor window and its duration must not exceed the descriptor
TTL ceiling. The declared use ordinal must be between one and the actual CLZ
maximum. Existing one-time and session-bound structural rules remain intact.

The helper derives TACP principal, CBD and CLZ identifiers and digests, lease
mode and window, source `credentialref:` and exact TAPB binding from those
replayed sources. It computes only the digest of the explicitly supplied runtime
`credref:` using the unchanged reference-digest helper. The runtime reference
itself is not serialized. It never rewrites `credentialref:` into `credref:` or
assumes matching suffixes identify the same credential.

Creation must be inside both the lease and supplied target-provider half-open
windows: their lower bounds are inclusive and their expiry bounds exclusive.
The entire broker lease need not fit inside the TAPB window. The broker provider
and adapter need not equal the target-authentication provider or implementation.
The explicit factor must appear in at least one of the TAPB's declared profiles;
the CBD does not identify the secret's factor. Full selected-profile coverage,
command windows, session and lifecycle joins remain the responsibility of the
unchanged target-authentication chain verifier.

## Native ownership and cost limits

Capture requires complete exact base wrapper families, exact nested families,
constructor-normalized native tuples and the expected enum families before
calling their existing serializers. Native string and integer aliases, boolean
integer aliases, floats, unsupported objects, missing slots and malformed
references fail closed. Ordinary existing constructors may normalize valid
native input lists and enum strings into those tuple and enum fields; such
normally constructed records remain supported.

Each captured document separately has a 1 MiB canonical ASCII byte budget,
8192-node budget and depth-12 limit. Native strings are at most 512 bytes and
integer magnitude is at most `2**63 - 1` before decimal conversion. Existing
broker schema arrays remain bounded to 100, modes to two and target-provider
profiles and operations to their closed vocabularies. Repeated subtrees, escaped
quotes and backslashes, keys, punctuation and scalar bytes are charged before
new canonical JSON serialization, source reconstruction or hashing. These are local software
cost bounds, not credential authority, TTL changes or a combined 1 MiB budget
across all inputs. Pre-entry work by existing caller constructors is not covered.

Captured documents and returned objects are detached. Later mutation of caller
sources or a returned dictionary cannot rebind a previously returned TACP.
This is an input-ownership boundary, not a concurrent-mutation guarantee or a
sandbox against arbitrary code with access to process memory.

## Historical integrity and non-capabilities

The helper evaluates declared historical validity at `created_at`. It does not
observe present time, check present revocation, query a use ledger or establish
that the requested ordinal is still available. A valid historical provenance
can be inspected after expiry without granting current permission.

CBD and CLZ bodies are descriptive sources. The CLZ carries request, approval,
renewal and issuance references or hashes, not their complete authoritative
bodies. A mapping-attestation digest is an explicit unverified declaration,
not authentication of a reference translator. Source hashes cannot establish
actual issuance, consent, independent approval, signature authenticity,
credential delivery, real factor contents, replay availability or target
authority. This leaf performs no use consumption, renewal, refresh, logout,
revocation or cleanup and makes no independent source-truth claim.

Existing schema versions, TACP fields, content-address domains, canonical bytes,
effects and claims remain unchanged. The old contract parsers and chain verifier
are not retroactively promoted to broker-body verification. The new helper
provides an explicit source-replay boundary; its fixed effects and claims still
grant no authority, live readiness, production acceptance, qualification or
parity. Live mapping, custody, deployment and independent acceptance remain
separate responsibilities.
