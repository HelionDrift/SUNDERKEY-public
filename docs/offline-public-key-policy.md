# Supplied RSA And EC Public-Key Policy Review

The GE-D22-S06 component parses supplied DER SubjectPublicKeyInfo public-key
bytes. It accepts RSA and elliptic-curve public keys only. It compares the
parsed modulus size and exponent or curve name with a caller-supplied policy.
The policy values are not SUNDERKEY recommendations or a standards verdict.
The example uses a toy elliptic-curve public key and a deliberately different
supplied curve allowlist to show a bounded review signal.

Only canonical base64 of canonical public SPKI bytes is accepted. Private-key
DER, unsupported public-key families, duplicate key identifiers, malformed
encoding, and oversized inputs are rejected. The report contains the parsed
public properties and a SPKI digest, never raw key bytes. It does not load a
private key, sign or verify a message, contact a provider, assess effective
policy, or prove key use. A mismatch is an unsigned review question, not a
finding or qualification result.

The checked inert envelope is
[`examples/offline-public-key-policy-component.json`](../examples/offline-public-key-policy-component.json).
It requests no network, filesystem, process, or credential resource and needs
the original supplied model for replay. Use only public, sanitized data. The
public-key decoding interface follows the
[`cryptography` serialization documentation](https://cryptography.io/en/50.0.2/hazmat/primitives/asymmetric/serialization/).
