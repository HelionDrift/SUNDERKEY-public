# Inert Cloud KMS wire codec

This slice describes two exact Cloud KMS requests and verifies supplied response
bytes using the existing raw Ed25519 codec. It is not a transport, provider,
signing invocation, dispatch command, SDK integration, or authenticated cloud
receipt. It opens no connection, reads no environment or credential, performs
no IO, generates no key, and makes no retry decision. All effects remain `none`.
GCP `us-west3` remains planning only; no signed D014 selection or production
acceptance is supplied.

## Exact request descriptions

`encode_gcp_kms_public_key_request(binding)` returns a frozen
`GcpKmsWireRequest` describing the default-format GET:

```text
GET https://cloudkms.googleapis.com/v1/{numeric-key-version-name}/publicKey
```

Its body and query are empty, and its fixed public header is
`Accept: application/json`. It does not request an alternate public-key format.
`encode_gcp_kms_sign_request(request)` describes:

```text
POST https://cloudkms.googleapis.com/v1/{numeric-key-version-name}:asymmetricSign
```

The POST headers are fixed `Accept: application/json` and
`Content-Type: application/json`. They are derived locally, cannot be overridden,
and contain no authorization material. The POST body is deterministic ASCII JSON
containing only standard-base64 `data` and decimal-string `dataCrc32c`. It
preserves the existing request's raw signing bytes, including domain separators,
without prehashing or reserializing
the signed document. No `digest`, digest CRC, endpoint override, authorization
header, credential, query override, retry setting, or dispatcher exists.

The existing codec validates one explicit numeric key version, SOFTWARE
`EC_SIGN_ED25519`, strict raw public-key material and its independent SHA-256
pin. This wire layer composes the codec's binding/request capture helpers, not
another cryptographic implementation. The frozen descriptor owns reconstructed
source records, method, fixed origin, exact path, immutable body bytes, body
hash and domain-separated wire request hash. The hash domain is
`sunderkey.gcp-kms-wire-request.v1` and includes fixed headers, public pins and
original request identity. Encoding, export and every response-consumption
boundary revalidate all source and derived fields. Late mutation cannot retain
an old descriptor.
Exports are detached dictionaries; exported body data may be sensitive and
should not be logged or persisted without the existing exact custody policy.

## Response bytes and HTTP semantics

`verify_gcp_kms_public_key_from_bytes(description, *, status_code,
response_bytes)` returns pinned raw public bytes after local validation.
`verify_gcp_kms_signature_from_bytes` returns the existing repository-format
signature string after mathematical verification over the original raw input.
Each requires the correct exact descriptor family and operation.

The local codec requires native integer HTTP status `200`. All other statuses,
including redirects, accepted/asynchronous status, empty-body success, partial
success and errors, are rejected before reading or parsing the supplied body.
Booleans, integer subclasses, floats, strings and status enums cannot substitute
for the native integer. No provider error body is trusted, reflected as advice,
or used to suggest a retry. This is a deliberately narrow local acceptance
policy, not a claim that no other HTTP status can exist at the provider.

Successful input must be 1 through 16,384 exact native bytes and strict UTF-8
containing one JSON object. Duplicate keys are rejected at every level,
including escaped-key aliases and unsupported nested fields. Floats, exponents,
nonfinite constants, excessive integer values, non-ASCII strings, invalid
encoding, trailing objects, excessive fields, deep structures and excessive
nodes are rejected. Bounds are depth 4, 64 JSON nodes, 16 fields per object,
4,096 characters per string, and integer magnitude at most `2^63 - 1`. These are
local limits, not assertions about Google service limits. A quote-aware depth
scan runs before JSON decoding. Whitespace and field order do not change
verification; PEM newline escapes retain their original decoded bytes.

The parsed object goes directly to the existing closed default-PEM or raw-data
response verifier. That preserves CRC32C checks, canonical base64/SPKI,
algorithm/protection/version consistency, independent public-key pins, exact
raw-data flags, strict Ed25519 R/S and signature verification. CRC and a claimed
`verifiedDataCrc32c` are not signer or provider authentication by themselves.
No alternative public-key payload, unknown field or digest-signing claim is
accepted as a fallback.

## Unchanged authority and custody boundaries

A supplied status and response body cannot prove TLS origin, Google provenance,
actual key version selection, current key state, IAM, account custody, signing
time, retention or audit durability. Local request correlation and signature
validity do not confer current authority. No result is `VerifiedPrincipal`, a
release permission, a production receipt, qualification or a live-use gate.
Deterministic repeated verification consumes no assertion or replay ledger.
Actual admission still requires the existing exact trust, scope, subject,
profile, expiry, revocation, consumption and custody checks.

Existing maximum raw signing capacity of 65,536 bytes is retained. The response
byte bound is independent of request size. Existing typed `signing_bytes()`
methods remain the source of canonical input. D012 release-head canonical bytes
are specified separately by an explicit [V1 pure byte profile](release-head-signing-profile-offline.md),
not selected by this wire codec or the unchanged signing port. This module does
not implement that production signer. No retention period, legal hold,
key lifecycle or recovery policy is selected.

Google's default GET path and empty body, and the raw-data POST path/body, are
documented in the official
[getPublicKey reference](https://docs.cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys.cryptoKeyVersions/getPublicKey)
and [asymmetricSign reference](https://docs.cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys.cryptoKeyVersions/asymmetricSign).
Public REST documentation was checked on 2026-09-28. No
provider API, authenticated request or customer resource was accessed.

## Software checks

Run `python -B -m unittest tests.agents.test_gcp_kms_wire -v` with `PYTHONPATH=src`.
Tests import only the existing fixed public material and pure fixture helpers
from `test_gcp_kms_ed25519`. Those helpers use the established public identity
vector, public-key serialization and independent CRC calculations, not private
material or random signing. Checks cover deterministic bodies and complete
capacity, strict fixed-vector crypto, duplicate fields at all levels, bounded
native bytes, HTTP semantics, late mutation, ownership and exact correlation.
All software results remain offline and nonqualifying.
