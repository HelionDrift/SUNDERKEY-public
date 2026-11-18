# Supplied X.509 SAN reference arithmetic

This R0 component compares one caller-declared reference identifier against the `subjectAltName` entries of one caller-supplied DER certificate. Its output is unsigned, source-addressed offline evidence. It neither acquires a certificate nor authenticates a service.

Ownership is the existing AOE-GE-D22-S03 profile, `crypto.pki-x509-validation` capability, AV-GE-D22-S03-01 vector, IWP2-AOE-GE-D22-S03 package, IW2-016 wave, AOE-GE-D22-CMD commander, AOE-HQ-07 group, and AOE-HQ-19 independent validator. The existing blueprint digest is `sha256:72a694de93739620178883eb4744577c819660d619bcb1db1a0c4f1eb4e3cfd0`. This is partial A7.4 evidence only and changes no qualification or live-use gate.

## Closed input and API

The exact native model has six fields:

```json
{
  "schema_version": 1,
  "source_id": "synthetic-san-test",
  "certificate_der_base64": "<canonical padded standard base64 of one DER certificate>",
  "reference_kind": "dns_id",
  "reference_value": "www.example.test",
  "wildcard_matching_permitted": true
}
```

The alternative reference kind is `ip_id`, with canonical IPv4 or IPv6 text. The wildcard switch is still required for that kind but has no effect. `source_id` is a local label, not authenticated provenance. All model fields must have exact native JSON types; no unknown fields, subclasses, floats, nonfinite values, duplicate raw keys or normalized scalar aliases are accepted. The byte entrypoint accepts exact bounded ASCII JSON bytes, not a file path.

The public operations are `analyze_supplied_x509_san(model)`, `analyze_supplied_x509_san_bytes(*, model_bytes)`, and `verify_supplied_x509_san_analysis(report, *, model)`. `X509SanAnalysis` supports direct construction, `from_dict`, `from_json`, `to_dict` and `to_json`. The wrapper owns canonical JSON. Every reconstruction recomputes all SAN observations from the embedded original DER; the separate verifier also recomputes from the separately supplied original model. The report embeds the entire caller-supplied base64 DER model. It is not sanitized for publication. A SHA-256 address detects changes to this local representation, not whether an issuer authenticated a subject.

## Named matching subset

The rules are selected from [RFC 9525 sections 6.2 to 6.4](https://www.rfc-editor.org/rfc/rfc9525.html#section-6.3) and the [RFC 5280 SAN form](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.6). A DNS reference must use an ASCII non-IDN preferred-name form, without a terminal dot, wildcard or U-label. A presented DNS-ID with the same form compares label by label with ASCII case folding. When caller policy permits, a single complete leftmost `*` label can match exactly one reference label, including in `*.test` versus `www.test` arithmetic. It does not match the apex or two or more labels. Partial or misplaced presented wildcards are ignored for matching. This component does not determine whether wildcard use is safe for a public suffix or application.

An IP reference compares the exact four or sixteen parsed address octets to a SAN iPAddress value. Canonical IP text is required; scoped IPv6 zone identifiers and network-prefix references are refused. A network-prefix-shaped iPAddress SAN is refused as outside the RFC 5280 SAN address shape, not matched to an IP-ID. DNS-like text in Common Name is never considered. Decodable other GeneralName families, invalid presented non-wildcard DNS syntax and IDNA/U-label conversion remain explicit unassessed observations. Malformed or unsupported SAN decoding is refused as a domain input error, not presented as an unassessed decoded entry. A known matching DNS-ID or IP-ID can coexist with unrelated unassessed names; the arithmetic match is still not authenticated identity. Absence of a supported match is only an observation about this supplied certificate and declared reference, not a conclusion about other credentials or a real TLS session.

The certificate parser requires one canonical DER certificate with no trailing data. It does not validate that certificate's signature, path, root, time, EKU, name constraints, revocation, issuer binding, IDNA semantics, or application identity. No network, provider, target, process or credential port is called. Flags for trust, service authentication, positive use and qualification are fixed false; every effect is `none`.

## Finite software bounds

One DER certificate is limited to 65,536 bytes, the canonical model to 131,072 bytes and the canonical report to 262,144 bytes. At most 128 SAN entries and 128 extensions are observed. Native document limits are 4,096 model nodes, 16,384 report nodes and depth 12. The complete public operation has one 33,554,432-unit cumulative software-work ceiling. Raw lexical bytes, native nodes, copy, DER parsing allowance, retained report shape, canonical encodings, equality comparisons and all report/model addresses are conservatively charged before this component's first SHA-256. The separate-original verifier charges both plans under that same operation budget before hashing either. Lowering a ceiling can cause an explicit software refusal; it is not a certificate judgment. The parser library has separate internal work not claimed as a universal constant-time operation.

This component is intentionally narrower than full RFC 9525 or PKIX. In particular, supplied preferred-name syntax and the wildcard switch do not establish browser acceptance, certificate issuance policy, current clock truth, authenticated issuer control, TLS admission or an approved security action.
