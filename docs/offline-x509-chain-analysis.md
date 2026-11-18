# Supplied X.509 chain analysis

`sunderkey.offline_x509_chain_analysis` implements a finite, offline structural
and signature analyzer, not a certificate trust service. It uses the existing
locked `cryptography==49.0.0` dependency and installs nothing.

## Existing ownership

The component belongs to specialist `AOE-GE-D22-S03`, capability
`crypto.pki-x509-validation`, vector `AV-GE-D22-S03-01`, package
`IWP2-AOE-GE-D22-S03` and wave `IW2-016`. The domain commander is
`AOE-GE-D22-CMD`, group commander `AOE-HQ-07` and independent validator
`AOE-HQ-19`. This partial implementation does not change the original D016,
Phase 168 contracts, six reference SDKs, qualification or live-use gates.

## Explicit inputs and software bounds

`analyze_supplied_x509_chain(model)` accepts only this closed native JSON shape:

```json
{
  "schema_version": 1,
  "chain_der_base64": ["<canonical base64 public certificate DER>"],
  "declared_terminal_sha256": "sha256:<64 lowercase hexadecimal characters>",
  "evaluated_at": "2026-09-28T12:00:00Z"
}
```

Certificates are supplied in leaf-to-declared-terminal order. The exact last
certificate must match the supplied terminal digest. The analyzer does not
discover, fetch, reorder or complete a path. A single supplied terminal is
explicitly incomplete. Duplicate certificates are rejected.

The fixed software subset allows 16 certificates, 65,536 DER bytes per
certificate, 524,288 aggregate DER bytes, 128 extensions per certificate and
issuer public keys no larger than 8192 bits. Native JSON is bounded to 1 MiB,
8192 visited nodes and depth 12. Strings are printable ASCII and at most the
canonical base64 size for one certificate; numeric metadata uses signed64.
These are local software-cost limits, not certificate security-strength
approval, provider capacity or runtime policy. Unsupported signature or
issuer-key support yields an incomplete result.

Native families, scalar types, structural punctuation, repeated subtrees and
escaped string sizes are checked before serialization or hashing. Booleans,
floats, subclasses, cycles, excessive integers and unknown fields cannot stand
in for supported inputs. Base64 must decode and re-encode identically; the
pinned DER parser and exact DER serialization reject malformed or trailing
certificate data. No PEM, private-key or general ASN.1 input is supported.

## Actual checks and their limits

Each adjacent pair undergoes issuer-name comparison and cryptographic
signature verification. A matching issuer name with the wrong signing key is
a signature violation, not verified issuance. The library's direct-issuer
method is only a name/signature check, not complete certificate validation.
[Cryptography X.509 reference](https://cryptography.io/en/latest/x509/reference/#cryptography.x509.Certificate.verify_directly_issued_by)

Nonterminal certificates are checked at the caller-supplied evaluation instant.
Their validity includes both endpoints. Intermediate issuers require CA basic
constraints and, when key usage is present, certificate-signing permission.
Path-length accounting excludes the target leaf and self-issued intermediate
certificates. Self-issued name equality does not prove a self-signature or
trust. [RFC 5280 validity and basic constraints](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1.2.5)

BasicConstraints and KeyUsage critical extensions are processed, including
leaf key-signing-without-CA and empty-key-usage contradictions. On every
nonterminal certificate, a path-length value with present key usage that
denies certificate signing is a violation. Absent key usage does not create
an additional requirement in this subset. A CA target leaf is not
automatically rejected: no application purpose is selected.
Other critical extensions on nonterminal certificates make the result
incomplete, including recognized but unimplemented name constraints and EKU.
Unimplemented noncritical extensions are not evaluated. Full PKIX validity is
never claimed. [RFC 5280 extension handling](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2)

The last certificate is a caller-declared terminal, never an authenticated
trust root. Its validity, CA bits, key usage and critical extensions are
observations only. Its expiry, self-signature or embedded path-length value
does not silently become an acceptance rule. Selecting and authenticating a
trust anchor remains separate policy. [RFC 5280 path-validation inputs](https://www.rfc-editor.org/rfc/rfc5280.html#section-6.1.1)

The analyzer does not evaluate complete distinguished-name normalization,
hostname, application purpose, EKU, name constraints, certificate policy trees,
algorithm-strength requirements, revocation, OCSP, CRLs, AIA or root stores.
It uses no live clock, callback, network, process, credential or keystore.
Public names and SAN values are not emitted, but fingerprints remain
potentially sensitive evidence and are not automatically certified sanitized.

## Integrity is not trust

The detached `X509ChainAnalysis` wrapper supports `to_dict`, `to_json`,
`from_dict` and `from_json`. Its address binds the ordered source fingerprints,
supplied evaluation time, observations, limits and fixed nonauthorizing flags.
Parsing rejects duplicate fields and reconstructs metadata relationships, but
cannot prove declared certificate facts without the original DER sources.

`verify_supplied_x509_chain_analysis(report, model=model)` separately recomputes
every observation from the complete supplied source model and compares exact
canonical bytes. Coherently readdressed metadata is not a substitute for this
source replay. Neither operation authenticates the input provenance, selected
terminal or supplied time, nor establishes current authority or target truth.

`supported_checks_outcome` is `pass`, `violations` or `incomplete` for this
finite subset only. Violations remain available when incomplete checks also
exist. All reports set `full_pkix_validated`, `trust_established`,
`positive_use_approved` and `qualification_claimed` to `false`; all declared
authority, target, execution, routing, qualification, deployment and provider
effects remain `none`. No assessment receipt, admission or signature is issued.

The test helper `synthetic_chain_model()` returns only public DER for a fixed,
disposable synthetic chain. Its test-only ephemeral keys are not operational
keys or a selected trust root. Tests also generate disposable RSA/ECDSA
fixtures, verify adverse chains, and demonstrate that metadata integrity and
source replay do not confer trust or qualification.
