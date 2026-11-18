# Enterprise identity runtime

## Purpose

This repository-only increment closes two bounded enterprise identity gaps. It
verifies a compact OIDC JWS offline against an authenticated, policy-bound
pinned keyset, and it exposes a separately injected SCIM dispatch boundary for
commands that the existing enterprise identity contracts already admitted.

The module does not include identity provider discovery, JWKS retrieval, a
network client, a filesystem key loader, credentials, deployment logic, or
production authority. It does not claim a live identity integration.

## Offline OIDC verification

`verify_pinned_oidc_jws` accepts one compact token, one
`EnterpriseIdentityPolicy`, one `AuthenticatedPinnedOidcKeyset`, an injected
`AuthenticatedOidcKeysetVerifier`, a canonical evaluation time, and one replay
control. The keyset binds its stable ID, policy digest, issuer, audience,
validity interval, authentication evidence digest, each allowed `kid`, and the
exact SHA-256 fingerprint of each RSA SubjectPublicKeyInfo. The only accepted
JWS algorithm is RS256. The protected header must contain exactly `alg`, `kid`,
and `typ`, and `typ` must be `JWT`.

The verifier performs these checks before producing an assertion:

1. Strict token size, ASCII, compact serialization, base64url, JSON, duplicate
   member, header shape, algorithm, type, key ID, key type, and key size checks.
2. Exact policy, issuer, audience, keyset validity, authenticator identity, and
   injected authentication-verifier checks before key use.
3. Exact `kid` and RSA SubjectPublicKeyInfo fingerprint checks before signature
   verification. Replacing a key under an allowed `kid` fails closed.
   Discovery, JWKS URLs, embedded keys, critical extensions, and algorithm
   negotiation are not accepted.
4. Exact issuer, audience, tenant, optional expected subject, session,
   assurance, authentication method, issued-at, not-before, expiry, and
   authentication-time checks.
5. Either an exact expected nonce or a required unseen replay ID. The receipt
   contains only a digest of that binding.
6. Optional exact string claim requirements for non-reserved claims.
7. Admission through `admit_sso_assertion` from the existing enterprise
   identity contract module.

The result contains a `VerifiedSsoAssertion`, its policy decision, and a
content-addressed receipt. The receipt binds the keyset ID and digest plus the
selected `kid` and exact public-key fingerprint. It never stores the compact
token or a public or private key.

## Injected SCIM dispatch

`dispatch_validated_provisioning` accepts an existing `ProvisioningCommand`,
the policy and actor binding used by `validate_provisioning_command`, exact
resource version and content preconditions, an idempotency ledger view, a
short-lived `ProvisioningDispatchAdmission`, an injected authenticated
admission verifier, an environment-attested dispatcher, and an injected atomic
idempotency reservation and completion store.

The runtime calls the dispatcher at most once and only when all of these
conditions hold:

1. The existing validator returns an allow decision, including an active actor
   binding whose inclusive `valid_from` and exclusive `valid_until` contain the
   explicit `evaluated_at`. A failure produces
   `actor_binding_outside_validity` and denies before any injected callback.
2. Tenant, policy digest, command digest, decision digest, idempotency key,
   environment, dispatcher identity, dispatcher attestation digest, admission
   verifier identity, and idempotency store identity exactly match the
   admission.
3. The admission has an explicit `approved=True` value with no permissive
   constructor default, is active, and names only a test or staging
   environment.
4. The injected verifier authenticates the exact content-addressed admission.
5. The dispatcher exposes one stable ID, environment, attestation digest, and
   dispatch method, all matching the admission before reservation or dispatch.
6. The idempotency key is absent from the supplied ledger view and the atomic
   store reserves it before dispatch. A reserved or completed key rejects
   replay and concurrent dispatch.

This actor-binding check uses the supplied evaluation time, not a new live
clock observation. Historical binding inspection remains separate from fresh
provisioning admission. See
[`offline-enterprise-provisioning-currentness.md`](offline-enterprise-provisioning-currentness.md)
for the boundary and regression controls.

There is no automatic retry. A dispatcher exception, invalid return type,
postcondition mismatch, or completion-store failure fails closed after the
single call. A reservation remains held when dispatch or postcondition checks
fail, so the caller cannot silently retry the external effect. The returned
`ScimDispatchResult` must bind the exact tenant, command digest, idempotency
key, operation, resource kind, new version, content digest, tombstone state,
and session revocation state. Only those minimal fields cross the boundary.
Raw directory payloads are not accepted or serialized. After exact
postconditions pass, the store atomically completes the reservation. The
receipt binds the admission ID and digest, approval authentication evidence,
environment, dispatcher identity and attestation digest, store identity,
reservation ID and digest, and completion ID and digest.

## Receipts and effects

`EnterpriseIdentityRuntimeReceipt` is immutable, deterministic, and
content-addressed. Its JSON schema is
`registry/schemas/enterprise-identity-runtime-receipt-v1.schema.json`.

Every receipt declares:

- no authority grant;
- no built-in network activity;
- no credential values;
- no production effect;
- no qualification effect; and
- no raw directory payloads.

The SCIM boundary deliberately rejects production admissions. A later
infrastructure phase must provide an approved identity provider, key custody,
authenticated keyset service, admission verifier, replay store, durable atomic
idempotency store, environment-attested dispatcher, monitoring, and production
change control before any live identity claim is valid.

## Public API

- `EnterpriseIdentityRuntimeError`
- `EnterpriseIdentityRuntimeReceipt`
- `AuthenticatedPinnedOidcKeyset`
- `AuthenticatedOidcKeysetVerifier`
- `AuthenticatedAdmissionVerifier`
- `AttestedScimDispatcher`
- `AtomicScimIdempotencyStore`
- `OidcVerificationOutcome`
- `ProvisioningDispatchAdmission`
- `ScimDispatchOutcome`
- `ScimDispatchResult`
- `ScimIdempotencyReservation`
- `ScimIdempotencyCompletion`
- `ScimDispatcher` compatibility alias for `AttestedScimDispatcher`
- `dispatch_validated_provisioning`
- `verify_pinned_oidc_jws`
