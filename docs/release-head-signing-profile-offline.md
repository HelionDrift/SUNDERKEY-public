# Offline D012 Release-Head Signing-Byte Profile

This additive V1 profile specifies deterministic bytes for an existing
`ReleaseHeadSigningRequest` and reconstructs those bytes from an existing
`SignedReleaseHeadDescriptor`. The approved D012 next steps include release-head
signing and offline verification. Specifying these bytes implements a part of
that step, not its authority, signer, verifier, deployment or acceptance layers.

The module has no signer, public-key resolver, provider transport, credentials,
clock defaults, storage, activation operation or `ReleaseHeadVerificationReceipt`.
It neither generates a signature nor verifies one. It does not authenticate an
offline-root authorization digest, assert currentness, check a trusted rollback
anchor or qualify a provider.
The separate [offline verification preview](release-head-offline-verification.md)
now checks an Ed25519 signature and explicit caller-supplied anchors, but it
still cannot issue a production verification receipt or establish trusted
currentness.

## APIs and Fixed Representation

- `release_head_signing_bytes(request)` accepts the exact existing native
  `ReleaseHeadSigningRequest` family.
- `signed_release_head_signing_bytes(signed_head)` accepts the exact existing
  `SignedReleaseHeadDescriptor` family.

Both return native bytes. The fixed prefix is:

```python
b"SUNDERKEY\x00PRODUCTION-CUSTODY-RELEASE-HEAD\x00D012\x00V1\x00"
```

Append canonical ASCII JSON with exactly this projection:

```json
{
  "schema_version": 1,
  "head": {
    "deployment_id": "deployment.offline",
    "ledger_sequence": 1,
    "entry_id": "entry.genesis",
    "entry_sha256": "sha256:<64 lowercase hexadecimal characters>",
    "previous_head_sha256": null
  },
  "signer_key_id": "key.release.offline",
  "offline_root_authorization_sha256": "sha256:<64 lowercase hexadecimal characters>",
  "signing_algorithm": "Ed25519",
  "signed_at": "2026-09-28T12:34:56Z"
}
```

The displayed projection is descriptive. Actual bytes use sorted keys,
`separators=(",", ":")`, `ensure_ascii=True`, `allow_nan=False`, and no trailing
newline. The request's `requested_at` becomes `signed_at`. Reconstruction uses
the signed descriptor's exact `signed_at`, without timezone or precision
normalization. Only the existing UTC-second spelling is supported.

Transport request IDs are validated but excluded because an exported signed
head does not retain them. Signatures are excluded to avoid circular input.
The signed descriptor must contain 64 native signature bytes, but that length
check is not cryptographic verification. Changing a well-shaped signature does
not change the reconstructed bytes.

This V1 profile is explicitly Ed25519-only. It does not silently convert
`sha256_simulation`, Ed25519ph, another algorithm or an alternate spelling. A
consumer selects this V1 API explicitly; no profile guessing or fallback is
provided. Future profiles require an explicit versioned contract.

## Native Input, Ownership and Bounds

Source wrappers and their nested head must be exact existing families with
closed native dictionary field storage. Scalar aliases, floats, booleans as
integers, missing or unknown fields, malformed digests and invalid predecessor
relationships reject before serialization. Strings are bounded before scanning.

Identifiers retain the existing 1..256-character ASCII identifier subset.
Digests are exact lowercase `sha256:` values. The sequence is a native integer
in `1..9223372036854775807`. This is the finite supported subset of this new V1
profile, not a new bound on the unchanged public custody ports. Oversized
integers reject before decimal conversion. The total prefix plus JSON is bounded
to 4096 bytes.

Construction captures native source values, owns the projected dictionary and
rechecks source values and wrapper/storage identities before returning bytes.
Detected changes during construction fail closed, including a changed transport
request ID or signature even though those fields are not signed. No caller
storage is modified and the result contains no mutable source references.

Existing source dataclasses do not retain a creation-time fingerprint. A fully
valid replacement made before function entry is indistinguishable from valid
new caller-supplied material. Structurally incomplete or malformed forged
instances reject, but exact shape is not authenticity. This is not an atomic
snapshot guarantee against arbitrary concurrent mutation or proof of who
constructed the source.

## Compatibility and Fixed Vectors

Existing signing domains, schemas, ports and simulation signatures are unchanged.
The ledger head and its `previous_head_sha256` keep their existing meanings;
they do not become hashes of this signing payload or of a signed wrapper.

The synthetic fixtures freeze:

| Input | Bytes | SHA-256 of complete prefixed input |
| --- | ---: | --- |
| Genesis head | 493 | `c98a3b2da0ead441a32632632df2884d0a3a2c71199ee31b9e948a5f17898c54` |
| Successor head | 564 | `9f1ffcb2c0783051b982e64a9e2ea25aba802dc2389238414eda9b7d97d620ec` |

Tests also preserve the old head digest and a `sha256_simulation` signature
golden. A disposable synthetic Ed25519 key demonstrates exact raw-byte mapping
through the existing transport-free GCP KMS codec. It is not an authorized key,
a KMS invocation, a selected protection policy or a production deployment.

## Remaining Authority and Conformance Boundaries

An enrollment catalog signer authorization is limited to
`key_use="candidate_enrollment_catalog"`. It is not release-head signing
authority. A caller-supplied root digest, key ID or mathematical signature does
not establish the missing authorization, its currentness or deployment scope.

The existing complete verification receipt requires signature, predecessor and
rollback checks. These APIs never issue it. A later independent verifier must
establish the actual root-authorized signer, key lifecycle, exact predecessor,
trusted rollback state and appropriate time policy before claiming all checks.
Audit-before-sign custody, failure recovery and dual-control activation remain
separate requirements.

The unchanged Phase185 reference suite deliberately asks its simulated signer
to sign alternate-root and alternate-predecessor inputs before verifier rejection.
A future authority-enforcing signer may reject those inputs earlier. Resolve
that negative-fixture composition explicitly; do not weaken signer authorization
or claim this pure profile completes the common production conformance suite.

GCP `us-west3` appears only in a supplied synthetic test coordinate. This profile
selects no repository, region, key version, root, identity or operational policy
and supplies no target, deployment, provider, routing or qualification authority.
