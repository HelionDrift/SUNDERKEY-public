# Offline Cloud KMS Ed25519 Codec

## Scope and authority

`sunderkey.gcp_kms_ed25519` maps existing raw signing bytes and verifies the
consistency of supplied Cloud KMS-shaped responses. It has no transport, cloud
SDK, credential discovery, key generation, private key, signing service, retry,
store mutation or provider invocation. Its tests use fixed public material from
`IdentityGoldenVectorTests`, not an operational key or a real principal grant.

GCP and `us-west3` remain the planning assumption recorded in
`docs/d014-gcp-us-west-planning.md`. Fictional resource names in tests do not
select deployment resources, sign D014 or authenticate a Google Cloud response.
All results are offline and nonqualifying.

## Exact input and public-key binding

Construct `GcpKmsEd25519KeyVersionBinding` with an explicit complete numeric key
version name, `EC_SIGN_ED25519`, `SOFTWARE`, 32 raw public-key bytes and their
`sha256:` fingerprint. There is no latest-version alias, default project,
automatic algorithm substitution or implicit public-key enrollment. The raw
key must pass the existing strict canonical prime-order Ed25519 check.
Ring and key IDs use the native 1-to-63-character letter, digit, underscore,
and hyphen grammar, including underscore or hyphen starts. Project identifiers
and numeric project references are validated separately from those key IDs.

`build_gcp_ed25519_sign_request(binding, signing_bytes)` takes the exact bytes
from an existing typed `signing_bytes()` method. Principal trust policies,
scope grants, revocations and assertions already define their domain separators
and canonical JSON. Qualification policy and reviewer credentials have their
own signing domains. Do not replace those bytes with a content digest or an
operation-intent digest, remove a domain separator or reserialize the document.
The codec cannot infer whether arbitrary caller bytes are a prehash; the caller
must supply the correct typed input, and response verification checks that
exact input rather than its hash.

The frozen request owns a separately validated binding and immutable native
bytes. It records the input SHA-256, CRC32C and a domain-separated local request
hash binding the complete public-key declaration and raw request. Export and
verification reconstruct the request and reject stale derived fields or a
changed binding. This content address is local integrity metadata, not signed
authority or a replacement for the canonical signing bytes.

`to_dict()` returns `name`, standard-base64 `data` and decimal `dataCrc32c`.
`to_rest_body()` returns only `data` and `dataCrc32c`; `name` is the explicit path
parameter. Neither form contains `digest` or `digestCrc32c`.

Google documents `EC_SIGN_ED25519` as PureEdDSA over raw data. Its current
algorithm table lists it under SOFTWARE, not HSM, single-tenant HSM or external
protection. This codec rejects those protection choices and other algorithms.
It does not resolve a requirement for HSM custody by weakening the protocol.
See [key purposes and algorithms](https://docs.cloud.google.com/kms/docs/algorithms).

## Public-key and signature responses

`verify_gcp_ed25519_public_key_response(binding, response)` consumes an exact
parsed JSON dictionary in the default PEM response mode. Required fields are
`pem`, `pemCrc32c`, `name`, `algorithm` and `protectionLevel`. Optional
`publicKeyFormat` must be `PUBLIC_KEY_FORMAT_UNSPECIFIED`; an alternative
`publicKey` payload is not accepted alongside the PEM. The verifier checks the
PEM CRC32C, one unambiguous public SPKI block, canonical Ed25519 DER, exact
version/algorithm/protection and the independently pinned raw key/fingerprint.
LF and CRLF PEM line endings are supported, with CRC over the original bytes.
It returns raw public bytes, not a trust policy. See
[getPublicKey](https://docs.cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys.cryptoKeyVersions/getPublicKey).

`verify_gcp_ed25519_sign_response(request, response)` requires `signature`,
`signatureCrc32c`, `name`, `protectionLevel` and exact native boolean
`verifiedDataCrc32c=True`. `verifiedDigestCrc32c` may be omitted or exactly false,
consistent with a raw-data request. Checksums must be canonical decimal strings
in the uint32 range, not integers, floats or booleans. Unknown fields,
non-native values, malformed or oversized encodings and ambiguous responses
fail closed. The signature is exactly 64 bytes in canonical standard base64.

CRC32C is an integrity check, not signer authentication. After CRC and metadata
checks, the existing `identity._verify_ed25519` validates canonical R and S and
the signature against the pinned key over the original request bytes. The
return value is a repository-format unpadded base64url signature string, never
`VerifiedPrincipal`, a provider receipt or a release permission. See
[asymmetricSign](https://docs.cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys.cryptoKeyVersions/asymmetricSign)
and [data integrity guidelines](https://docs.cloud.google.com/kms/docs/data-integrity-guidelines).

These response shapes do not establish current key state, key purpose, IAM
permissions, account custody or authenticity of the supplied cloud metadata.
Caller pins and synthetic dictionaries are not authenticated cloud receipts.
This module accepts already parsed dictionaries; a future transport must also
reject duplicate JSON keys before parsing and preserve the checked raw bytes.

## Bounds and unchanged contracts

Local codec bounds are 1..65,536 signing bytes, 640 key-version-name characters,
4,096 PEM characters and 88 signature-base64 characters. These are explicit
limits of this offline codec, not claims about Google service message limits.
Fields and primitives are closed and dictionaries exported by records are
detached. No payload is logged or persisted by the codec.

The D012 `ReleaseHeadSigningRequest` and `ReleaseHeadSigner.sign_head` ports
carry typed head/root/signer metadata but do not specify canonical signing
bytes. Existing Phase185 reference tests use a synthetic JSON hash as their
signature. The separate additive [D012 V1 byte profile](release-head-signing-profile-offline.md)
now defines exact request and signed-head reconstruction without changing these
ports or simulation vectors. This codec neither selects that profile implicitly
nor implements a production signer, verifier or full conformance suite.

## Rotation, retention and replay

Each request binds one exact version and public key. An old response cannot
bind a new version, and relabeling it cannot satisfy a different key pin.
Historical mathematical verification against retained old public material
does not establish eligibility for new signing or current runtime use. Existing
SUNDERKEY trust, key-use, subject, profile, scope, expiry, revocation and replay
consumption checks remain mandatory and are not called or bypassed here.

Google does not automatically rotate asymmetric keys. New signing versions
require explicit application selection and public-key distribution; rotation
does not disable previous versions. See
[key rotation](https://docs.cloud.google.com/kms/docs/key-rotation).
Disabled or destruction-scheduled versions cannot sign. Destroyed versions
cannot create signatures and their public keys are no longer downloadable.
Retain public verification material before destruction according to the exact
custody policy. See [key version states](https://docs.cloud.google.com/kms/docs/key-states).

This codec chooses no retention period, legal hold, deletion, key lifecycle or
recovery policy. It proves no object retention, audit durability, release-head
lineage, CAS behavior, provider availability or production qualification.
Those obligations remain with the existing D012/D013 contracts and the complete
signed D014 and operational acceptance process.

## Focused software check

Run `python -B -m unittest tests.agents.test_gcp_kms_ed25519 -v` with
`PYTHONPATH=src`. The fixed-vector checks cover exact original bytes and strict
crypto, metadata and key substitution, CRC and JSON primitives, ambiguous PEM,
wrong domains/prehash replay, local bounds, detached ownership and explicit
version changes. No cloud signing operation or private-key fixture is required.
