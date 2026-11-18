# Authorized HTTP runtime boundary

## Purpose

The authorized HTTP runtime is a repository-only, fail-closed boundary for one
HTTP exchange during an explicitly authorized assessment. It bridges validated
SUNDERKEY authority and execution-control evidence to caller-supplied HTTP
infrastructure. It does not include a network client, DNS implementation,
credential resolver, secret provider, browser, exploit payload, or deployment.

The boundary does not grant authority or qualification. Both receipt fields are
fixed to `none`. A completed receipt proves only that the injected boundary
accepted its bound inputs and observed one backend call.

## Required bindings

Every call requires all of the following existing artifacts:

1. A `VerifiedAssessmentScope` produced by signed scope verification.
2. An `HttpRequestIntent` bound to that exact scope, task, technique, impact
   tier, session, request body digest, and request metadata.
3. An `ExecutionRequest` carrying the exact tenant, context, scope, target,
   session, lease, fence, policy, intent digest, and canonical intent byte
   length bindings.
4. An admitted `AdmissionReceipt` whose request and policy identifiers and
   digests match the execution request.
5. An `AuthorizedHttpPolicy` carrying the expected execution binding, execution
   policy, header allowlists, MIME allowlist, and byte ceilings.

Substitution of any scope, tenant, context, target, session, policy, request, or
intent identity causes a pre-send rejection.

## Injected interfaces

The runtime uses protocols supplied by the deployment:

- `RuntimeClock` provides canonical UTC and monotonic observations.
- `RuntimeSafetyMonitor` provides request-bound health, cancellation, and
  emergency-stop state.
- `DnsResolver` returns canonical IP address sets for an exact normalized host.
- `RequestBodyProvider` returns bytes for an already hash-bound request body.
- `HttpBackend` performs the single possible send.

No default implementation is included. A deployment must separately qualify,
configure, isolate, monitor, and operate each adapter.

## Enforcement sequence

The function `execute_authorized_http_exchange` performs these checks before a
backend call:

1. Validate every scope, admission, policy, execution, session, and intent
   binding.
2. Parse an absolute HTTPS URL and reject userinfo, query strings, fragments,
   encoded ambiguity, and non-canonical paths or hosts.
3. Re-evaluate the method, origin, host, port, path, technique, impact tier,
   exclusion, protected endpoint, time window, and scope budgets against the
   verified signed scope at the injected clock observation.
4. Require healthy, uncanceled, non-emergency safety state bound to the exact
   execution binding and request digest.
5. Enforce explicit request header, request byte, and request MIME limits. Raw
   authorization headers, cookies, credential-like headers, and probable secret
   material are rejected. JSON and form bodies receive field-aware inspection,
   including nested token and client-secret names. Malformed structured bodies
   are rejected when they cannot be parsed conclusively for screening.
6. Resolve a DNS name twice, check both answers against signed scope CIDRs and
   CIDR exclusions, and reject any answer change. Literal IP targets bypass DNS
   but still require signed scope containment.
7. Recheck safety state after DNS preflight and re-evaluate the signed scope at
   the final clock observation immediately before the send. A window or scope
   that expired during preflight produces a zero-call rejection, not a later
   response failure. The pure decision does not spend the scope budget again.
8. Pass `follow_redirects=False`, `maximum_attempts=1`, and the response byte
   ceiling to the injected backend.

Only one call to `HttpBackend.send` is possible. The runtime never retries.

## Response controls

After the call, the runtime rejects the response evidence if any of these
conditions hold:

- The backend reports more than one attempt.
- The backend followed a redirect or returned a redirect status.
- The body is incomplete or a backend byte limit was exceeded.
- The body exceeds the total response ceiling or its MIME-specific ceiling.
- The response lacks exactly one allowlisted `Content-Type` header.
- A declared `Content-Length` differs from the observed body length.
- A header is duplicated, forbidden, secret-bearing, or outside the response
  allowlist.
- Probable raw secret material is present in the response body.
- A declared JSON or form body cannot be parsed conclusively for secret
  screening.

A rejected response remains evidence of a performed network call. It is never
reported as a pre-send rejection.

## Evidence

Every terminal result is an `HttpExchangeReceipt` with:

- Exact scope, intent, admission, execution request, policy, and execution
  binding identities and digests.
- DNS attestation hashes without resolver secrets.
- Request and response body hashes and byte counts without body retention.
  A response body hash is recorded only after secret screening conclusively
  succeeds. Bodies rejected for size, secret content, or a screening failure
  do not place a plain SHA-256 digest in the receipt. Every non-completed
  receipt requires a null response body digest.
- A hash-chained transcript of validation, DNS, send, response, or failure
  checkpoints.
- Content-addressed transcript and receipt identifiers.
- Explicit `transport_called` and `network_call_performed` facts.

Known backend failures produce coded failure receipts. Unexpected backend
exceptions are reduced to `backend_exception`; exception messages are not
retained. Pre-send validation failures produce rejection receipts when enough
validated identity material is available.

`verify_exchange_receipt` accepts only canonical ASCII JSON or an exact object,
rejects duplicate and unknown fields, verifies every transcript link and hash,
recomputes the transcript and receipt content addresses, and requires completed
responses to carry the exact terminal reason `completed`, an exact status code,
MIME type, and body digest. The registry schema uses JSON Schema Draft 2020-12
and forbids additional properties throughout.

## Deployment obligations

Repository tests use deterministic fakes. A live deployment remains responsible
for network namespace isolation, egress routing, trusted DNS behavior, TLS
verification, certificate policy, proxy behavior, connection pooling, backend
timeout enforcement, body streaming limits, evidence storage, audit access,
external cancellation propagation, emergency-stop propagation, and independent
qualification. None of those infrastructure properties are claimed by this
repository-only boundary.
