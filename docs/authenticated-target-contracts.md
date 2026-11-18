# Authenticated Target Session Contracts

`sunderkey.authenticated_target_contracts` defines repository-only contracts for authenticated assessment sessions. The module adds no network client, credential resolver, browser driver, authentication implementation, or remote side effect.

## Security boundary

Every session is bound to one tenant, mission, signed scope, target, worker, session, fence reference, fence epoch, and fencing-token digest. Admission fails closed when any expected binding differs, the fence token differs, evidence is stale, an MFA checkpoint was declined, or a credential lease is revoked.

The module never accepts or serializes raw credentials, authorization header values, cookies, OAuth codes, OIDC tokens, refresh tokens, session tokens, or one-time passwords. Credential use is represented by an opaque lease reference. Request and response header values are represented only by SHA-256 digests. A secret-pattern scan also runs before canonical serialization.

## Authentication coverage

The contract vocabulary supports:

- HTTP Basic credentials by opaque lease reference
- bearer credentials by opaque lease reference
- isolated cookie sessions with a dedicated cookie-jar reference
- OAuth 2.0 authorization-code evidence with state and PKCE digests
- OIDC authorization-code evidence with state, PKCE, and nonce digests
- operator-confirmed MFA checkpoints using challenge and evidence digests, never an OTP
- refresh evidence that rotates the active lease reference
- logout, revocation, expiry, operator stop, and fence-replacement termination evidence

These records describe proof supplied by an injected transport or human checkpoint. They do not perform the described action.

## Authorization testing

`MultiPrincipalAuthorizationPlan` requires at least two distinct principals, a unique isolated session for every case, and at least one expected-denial case. This supports horizontal and vertical negative authorization testing without allowing identity state to leak between principals.

## Lifecycle

1. Build an `AuthenticatedSessionContract` from an exact context and opaque evidence references.
2. Call `evaluate_session_admission` with the independently expected context, current time, observed fencing-token digest, and any revoked lease references.
3. Only an admitted result can be passed to `prepare_authenticated_request`.
4. Supply only method, target, header, and body digests to request preparation.
5. Normalize caller-supplied response metadata with `normalize_authenticated_response`.
6. Record logout or revocation proof with `record_session_termination`.

All top-level records are content-addressed. `parse_contract` reconstructs records, rejects unknown fields, enforces the no-effects declaration, and recomputes the content address. The JSON Schema at `registry/schemas/authenticated-target-contract-v1.schema.json` validates the serialized wire forms.

The full reconstructed canonical JSON must match the supplied document as well.
Native schema-type substitutions cannot normalize into an unchanged claimed
identity. The [integrity controls](offline-contract-api-integrity.md) retain six
prior target-record identities and the existing no-effects admission behavior.

## Infrastructure still required

Production authenticated testing still requires separately approved and deployed infrastructure: a secret broker, browser or HTTP transport, redirect receiver, MFA operator interface, session store, revocation integration, egress enforcement, audit sink, and live target authorization. These contracts provide the binding and evidence boundary for those components but do not claim that those components exist.
