# Supplied-public-key compact JWS analysis

This partial offline algorithm belongs to `AOE-GA-D03-S05`, capability
`army.ga.d03.s05`, vector `AV-GA-D03-S05-01`, package `IWP2-AOE-GA-D03-S05`,
wave `IW2-006`, commander `AOE-GA-D03-CMD`, group commander `AOE-HQ-03` and
independent validator `AOE-HQ-19`. Its blueprint digest is
`sha256:71b4e9a6e6849d91012a981c4e8415862fd0a77bba2265d193ca9fa9cec5bb89`.
The relevant roadmap package is A2.7, OAuth and federation specialist, with
supporting token-boundary relevance to A2.6. This leaf does not complete either
package or qualify, activate, route or deploy a specialist.

SUNDERKEY already implements real RS256 OIDC verification and SSO admission in
`enterprise_identity_runtime.verify_pinned_oidc_jws`, using an authenticated,
policy-bound pinned keyset and separate nonce or replay checks. This leaf does
not replace, call or broaden that path. Its distinct result is detached,
unsigned metadata from one supplied compact token and one supplied public JWK.

## API and explicit inputs

`analyze_supplied_jose(model) -> JoseAnalysis` performs the bounded algorithm.
`verify_supplied_jose_analysis(report, *, model) -> JoseAnalysis` reruns it from
the exact original inputs. Invalid or unsupported input raises
`JoseAnalysisError`. `JoseAnalysis.to_dict()` returns a detached native document;
`to_json()`, `from_dict()` and `from_json()` support content-addressed replay.

The native model has exactly seven fields:

```python
model = {
    "schema_version": 1,
    "compact_jws": "supplied.protected-and-claims.signature",
    "public_jwk": {"kty": "EC", "crv": "P-256", "x": "...", "y": "..."},
    "expected_algorithm": "ES256",
    "expected_issuer": "https://issuer.example.test",
    "expected_audience": "sunderkey-synthetic",
    "evaluated_at": "2026-09-28T12:00:00Z",
}
```

The token and coordinates above are illustrative placeholders, not an accepted
fixture. The test helper `component_fixture()` returns a reproducible,
public-only synthetic model, using an intentionally public test key. It is not
an operational token or credential. The caller must supply all fields: there
is no clock, provider, key discovery, identity policy, implicit trust root or
default algorithm. The evaluation instant is a caller declaration, not an
independently observed current time.

## Signature and key subset

The caller selects exactly ES256 or RS256. The protected `alg` must match it;
there is no negotiation or fallback. The protected header contains `alg` and
optionally `kid` and `typ`. A present `typ` must be `JWT` in this claims subset.
A present `kid` must match the supplied JWK's declared `kid`; it never selects
another key. Embedded keys, remote key URLs, certificates, critical extensions,
unencoded payloads, nested JWTs, JWE, HMAC, `none`, PASETO and macaroons are outside
this finite subset. No pointer is fetched or interpreted as authority.

The EC public core is exactly `kty`, `crv`, `x`, `y`, with `EC`, `P-256`, and
canonical 32-octet coordinates. Constructing the actual cryptography public key
validates the curve point. ES256 requires a 64-octet JOSE signature containing
two fixed-width, unsigned, big-endian scalars. The analyzer converts these to
DER only for the pinned cryptography verifier. It verifies the original ASCII
protected-and-payload signing input, never reserializing its JSON first. Both
valid low-S and high-S signatures remain supported. Neither implies a unique
token identifier or replay prevention.

The RSA public core is `kty`, `n`, `e`, with `RSA` and minimal positive
Base64urlUInt encodings. This software subset permits odd 2048 through 4096-bit
moduli and an odd exponent from 3 through the four-octet range, smaller than the
modulus. Signature width is the ceiling of modulus bits divided by eight.
RS256 uses PKCS1v1.5 and SHA-256. This is signature verification, not encryption.
The 4096-bit ceiling is a local cost bound, not a universal JOSE limit.

Optional JWK metadata is limited to `alg`, `use`, `key_ops`, `kid`: when present,
algorithm must match, use must be `sig`, and operations must be exactly
`["verify"]`. Their absence creates no implicit key provenance or authority.
Private RSA/EC fields and symmetric key material are rejected, not logged or
serialized. The production module does not generate or load private keys.

## Claims and declared-time observations

Signature mathematics and claim checks remain distinct. A valid signature over
an incorrect issuer, wrong audience or expired window yields a mismatch report,
not an authenticated issuer. Issuer is compared exactly without normalization.
Audience may be a string or a bounded, nonempty, duplicate-free string list; the
caller-declared audience must occur exactly. Duplicate audience rejection is
this finite profile's constraint, not a universal JWT invalidity claim.

The supported NumericDate subset contains native integer epoch seconds from
zero through year 9999, with no skew or inferred dates. At the declared instant,
`nbf` is inclusive and `exp` exclusive. A present `iat` must not be later than
that instant. Present `iat` and `nbf` must precede `exp` when it exists. These
are explicit supplied-check profile conventions, not a complete JWT application
policy. Absent optional `iat` and `nbf` remain `not_present`; neither becomes an
invented timestamp. Missing `iss`, `aud` or `exp` yields incomplete coverage of
the selected checks, not a claim that these fields are mandatory for every JWT.

RFC 7519 allows fractional NumericDates. This leaf rejects fractional values as
unsupported input rather than calling every such JWT malformed. Other decoded
JSON floats and nonfinite numbers are also outside this compact software subset.
No subject, assurance, nonce, `jti`, key revocation, consent, audience ownership,
token purpose or actual current-use authority is established.

## Cost, integrity and limitations

Exact native model/report families are captured into owned data before hashing.
Per-document canonical ASCII JSON is at most 1 MiB, depth 12, 4096 native value
nodes, 65536-byte strings and 63-bit integer magnitude. Repeated shared subtrees,
escaping and punctuation are charged before serialization; cycles and native
subclasses fail closed. Compact input is at most 64 KiB, decoded protected
header 4 KiB, claims 32 KiB, signature 512 octets and claims 64 members.
Raw JSON has bounded bytes, depth and lexical value/key tokens before decoding,
duplicate-member refusal, a bounded integer hook and no float conversion.
Base64url is unpadded and must exactly reproduce after decoding and re-encoding.
JSON itself need not be canonically serialized inside a genuine signed token.

The detached report retains only source digests and sizes, algorithm/key
dimensions, bounded check states and fixed observation codes. It does not copy
the compact token, raw header, claim values, issuer/audience declarations or JWK
coordinates. Content-only parsing proves the report's closed shape and hash,
not its conclusions. Coherently readdressed false conclusions are denied by
full original-source replay. A changed evaluation time is another source, not
an instruction to authorize an old report for live use.

Every effect remains `none`. Issuer authenticity, key-origin authenticity, key
currentness, live-use approval, replay prevention and qualification are fixed
false. There are no callbacks, file readers, provider requests, discovery,
credentials, network or process invocation. Revalidating a forged wrapper does
not provide a sandbox against arbitrary malicious code in the same process.
The result is not an SSO assertion, mission grant, evidence admission or a
verified vulnerability finding. Historical replay remains nonauthoritative.

The supported mathematics and representation rules follow
[RFC 7515](https://www.rfc-editor.org/rfc/rfc7515.html),
[RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html),
[RFC 7517](https://www.rfc-editor.org/rfc/rfc7517.html),
[RFC 7519](https://www.rfc-editor.org/rfc/rfc7519.html) and the algorithm/input
boundaries of [RFC 8725](https://www.rfc-editor.org/rfc/rfc8725.html).
The repository pins cryptography 49.0.0; its
[EC implementation documentation](https://github.com/pyca/cryptography/blob/49.0.0/docs/hazmat/primitives/asymmetric/ec.rst),
[RSA verifier](https://cryptography.io/en/49.0.0/hazmat/primitives/asymmetric/rsa/)
and [signature conversion utility](https://cryptography.io/en/49.0.0/hazmat/primitives/asymmetric/utils/)
describe the underlying finite verification APIs.
