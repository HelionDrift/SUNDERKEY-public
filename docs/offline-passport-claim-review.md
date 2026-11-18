# Offline PASSporT Claim Review

This partial GA-D02-S02 algorithm decodes one supplied synthetic full-form SHAKEN PASSporT and compares its `orig` and `dest` telephone-number claims to separately supplied SIP signaling values. [RFC 8224](https://www.rfc-editor.org/rfc/rfc8224.html) requires a verifier to derive the originating identity from signaling rather than trusting the token's `orig` claim alone. [RFC 8588](https://www.rfc-editor.org/rfc/rfc8588.html) defines the SHAKEN `attest` and `origid` claims.

The supported JWS, header, and payload shapes are deliberately closed and bounded. Duplicate JSON keys and malformed base64url segments reject. A decoded attestation value is only an untrusted claim. The component never verifies the JWS signature, certificate chain, number authorization, request freshness, or call origin. It does not fetch the certificate URL, contact a SIP service, inspect audio, or assess a deepfake. The example signature is synthetic bytes, not a valid cryptographic endorsement.

The result hashes the token, certificate URL, and origination identifier. Telephone numbers are not emitted in the report. A mismatch is a review cue only, never an identity or fraud finding. The fixture is R0, dry-run, has no credential or resource grants, and requires original-model replay. No live authority or qualification is granted.
