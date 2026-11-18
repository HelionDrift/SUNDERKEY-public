# Authorized target-session runtime

## Purpose

The authorized target-session runtime is a repository-only, fail-closed
boundary for one target authentication attempt during an explicitly authorized
assessment. It connects existing verified scope, credential lease, and
execution-control evidence to an injected credential-session provider. It does
not include a credential resolver, identity provider, browser, network client,
payload, secret, or deployment adapter.

The runtime does not grant authority or qualification. Both effects remain
fixed to `none`. A completed receipt proves only that the injected boundary
accepted the exact bound evidence, observed one provider call, validated the
returned attestations, and recorded pending cleanup obligations.

## Required evidence

Every call requires these artifacts:

1. A `VerifiedAssessmentScope` produced by signed scope verification.
2. A `TargetSessionIntent` bound to that scope, task, technique, impact tier,
   HTTPS login target, requested isolated session, selected principal, and
   opaque credential references.
3. An `ExecutionRequest` bound to the exact tenant, task, scope, target,
   session, lease, fence, execution policy, intent digest, and cleanup
   obligation digest.
4. An admitted `AdmissionReceipt` whose request and execution policy
   identifiers and hashes match the request exactly.
5. An `AuthorizedTargetSessionPolicy` containing exact assessment, scope,
   target, technique, purpose, origin, execution binding, time limit, and
   cleanup and revocation obligations.
6. Either a content-addressed `CredentialLease` from the credential broker
   contracts or a content-addressed `OpaqueLeaseBinding` carrying the same
   required least-privilege fields.

Substitution of any identity or hash causes rejection before provider use.

## Injected interfaces

The deployment must supply five protocols:

- `TargetSessionRuntimeClock` supplies canonical UTC and monotonic
  observations.
- `TargetSessionSafetyMonitor` supplies exact request-bound health,
  cancellation, and emergency-stop state.
- `LeaseRevocationChecker` supplies exact lease-bound revocation evidence.
- `AtomicLeaseUseStore` atomically reserves and completes one exact tuple of
  lease identity, use number, execution request, execution binding, and
  requested session.
- `CredentialSessionProvider` performs authentication internally from one
  opaque credential reference and returns only typed session evidence.

No default implementation is shipped. Deployment qualification, isolation,
monitoring, identity integration, secret custody, provider networking, and
operations remain external responsibilities.

## Secret boundary

The provider command contains one opaque `credref:` value for the selected
principal. Only the injected provider receives that value. The audit view and
receipt retain a digest of the opaque reference, never the reference itself.
The provider must resolve and use credential material internally.

No runtime type accepts credential bytes or a credential value. A provider
result must state that no credential material was returned. Receipts and
transcript details contain identifiers, content hashes, stable codes,
timestamps, counters, and attestations only. Unexpected exception messages are
discarded.

## Pre-authentication enforcement

Before a provider call, `execute_authorized_target_session`:

1. Requires all scope, intent, execution, admission, policy, lease, tenant,
   task, target, session, fence, request, and content hashes to match.
2. Re-evaluates the absolute HTTPS login URL, method, path, technique, impact
   tier, exclusions, protected endpoints, time window, and budgets against the
   verified signed scope.
3. Requires the selected intent principal to equal the lease subject and the
   execution session to equal the requested isolated session.
4. Requires separate opaque credential references for all principals in a
   multi-principal intent.
5. Enforces exact lease purpose, target, technique, scope, session, issuance,
   expiry, and usage bounds.
6. Requires execution attempt one with no prior execution and constructs a
   provider command with `maximum_attempts=1` and `retries_allowed=false`.
7. Checks health, cancellation, emergency stop, revocation, and clock
   monotonicity before authentication.
8. Atomically reserves the exact lease-use tuple before the provider call.
   Reuse of a use number, concurrent replay, and reuse of a one-time lease are
   rejected before authentication.
9. Refreshes safety and revocation after a confirmed reservation, then samples
   the final pre-provider clock and rechecks signed scope and lease currentness.
   Reservation latency cannot carry expired, canceled or revoked authority
   into authentication. The earlier revocation proof remains in the transcript;
   receipt slots carry the fresh pre-provider and, if called, post-provider
   proofs.

Only one call to `CredentialSessionProvider.acquire` is possible. The runtime
never retries. Every provider call is followed by one completion attempt for
the reservation. A completion failure rejects the result and remains explicit
in the receipt.

A confirmed reservation followed by a pre-provider denial is also settled once,
with outcome `rejected_before_authentication` and `provider_called=false`.
Its receipt retains the exact reservation and either the confirmed completion
digest or `completion_failed`. It records zero authentication attempts and no
provider cleanup requirement. The runtime does not pretend the reservation was
never made, refund the use number, retry, or discard an uncertain completion.

## Provider postconditions

After a provider call, the runtime rechecks clock monotonicity, safety state,
and lease revocation. A completed result additionally requires:

- Exactly one observed authentication attempt.
- The requested session identifier and selected principal without
  substitution.
- An explicit isolated-session assertion.
- Exact session and principal attestation hashes derived from the command and
  returned expiry.
- A session expiry after the final observation and no later than the shortest
  of the runtime limit, lease expiry, or signed scope expiry.
- Exact cleanup and revocation obligation references.
- No returned credential material.

A provider call that fails produces `provider_failed`. A successful provider
response that fails any later requirement produces `postcondition_rejected`
and never publishes session identity as accepted evidence. Both states retain
pending external cleanup obligations because the provider may have created
remote state.

## Evidence and verification

Each terminal `TargetSessionReceipt` records:

- Exact scope, intent, execution request, admission, execution policy, runtime
  policy, binding, lease, and opaque lease-binding identities and hashes.
- Whether the provider was called and the exact authentication attempt count.
- Lease usage number, reservation key, atomic reservation identity and hash,
  completion hash or explicit completion failure, and revocation evidence
  hashes.
- Session and principal attestations only for a completed result.
- Explicit cleanup and revocation statuses.
- A hash-chained transcript and content-addressed transcript and receipt IDs.
- `credential_material_observed=false`, `authority_effect=none`, and
  `qualification_effect=none`.

Pre-call validation, safety, revocation, reservation, and clock failures
produce `rejected_before_authentication` receipts without provider use. An
already confirmed reservation remains visible in such a receipt. An
initial clock failure uses the already validated admission observation only to
timestamp deterministic rejection evidence; it does not substitute for a
runtime clock observation or permit execution. Known provider failures retain
only a stable code. Unexpected failures are reduced to `provider_exception`.

`verify_target_session_receipt` accepts canonical ASCII JSON or an exact
object. It rejects duplicate keys, unknown fields, non-canonical encoding,
broken transcript links, invalid effects, contradictory terminal states, and
altered content addresses. The registry schema uses JSON Schema Draft 2020-12
and forbids additional properties throughout.

A completed receipt requires the exact terminal reason `completed`, a
`completed` lease-use reservation status, and a non-null completion digest.
The constructor, strict verifier, and registry schema enforce the same
invariants.

## Deployment obligations

Repository tests use deterministic fakes only. A live deployment remains
responsible for credential vault access, provider authentication, network and
browser isolation, TLS verification, identity-provider policy, multi-factor
flows, timeout enforcement, session storage, cookie handling, session
revocation, durable implementation of the injected lease-use store, cleanup
verification, monitoring, audit access, external cancellation propagation,
emergency-stop propagation, and independent qualification. None of those
infrastructure properties are claimed by this repository-only boundary.
