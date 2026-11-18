# External API service and webhook contracts

`sunderkey.api_service_contracts` defines the versioned public boundary for an
eventual SUNDERKEY service. It is an infrastructure-independent contract layer.
It does not contain a web server, API client, webhook sender, network transport,
timer, worker, credential resolver, authorization engine, or execution path.

## Boundary and effect model

Every published request, response, subscription, delivery, and acknowledgement
contains an explicit `effects` object. Authorization remains external. Authority,
execution, network access, routing, scheduling, client behavior, server behavior,
and webhook delivery remain `none`.

The contract can communicate an intent or a reference to a result. It cannot
admit scope, schedule work, execute a technique, cancel a worker, or perform an
emergency stop. Those effects belong to independently verified control-plane
components. A future service adapter must authenticate the tenant and principal,
obtain an authorization decision, call those components, and publish only their
content-addressed results.

## API operations

`ApiRequestEnvelope` and `ApiResponseEnvelope` cover a closed operation set:

- create an assessment;
- submit a scope admission request;
- submit a schedule request;
- read assessment status;
- list evidence references;
- list finding references;
- read a report reference;
- request assessment cancellation;
- request an emergency stop.

The envelopes are immutable and versioned. Each request binds a tenant,
principal, principal role, and external authentication-context reference.
Responses repeat the binding and the exact request identity and content hash.
Payloads are opaque `ResourceReference` records. Evidence, findings, reports,
scope admission records, schedules, and status records never carry raw bodies,
credentials, exploit material, or direct object contents through this contract.

## Mutation controls

All mutating operations require an `idem:` idempotency key. Schedule, cancellation,
and emergency-stop requests also require the resource version the caller observed.
An implementation can therefore reject a retry with changed contents and reject a
stale state mutation. The contract itself records these requirements but does not
operate an idempotency store or update a resource.

Read operations reject idempotency keys and mutation resource versions. Evidence
and finding list operations require a bounded page request. Cursors are opaque and
have their own namespace. Page size, request body size, reference count, and the
declared request-rate budget all have hard ceilings.

## Stable errors

Rejected responses carry one `ApiError` and no resource or page result. The error
code comes from a stable closed taxonomy, including authentication, external
authorization, request validation, body and rate budgets, idempotency conflicts,
optimistic concurrency conflicts, missing scope admission, missing resources,
service availability, and already-recorded stops. The message is bounded human
text, while optional details are an opaque reference. Successful responses carry
no error. Single-resource reads require a resource. Paginated evidence and
finding lists may return an empty resource set with `returned_count: 0` and a
page result, so an empty page is not misclassified as a rejected response.
The response contains at most 1,000 resource references, matching its
published JSON Schema; the request budget may impose a lower limit.
Exchange verification reconstructs both typed documents from their exact
content addresses before checking request binding, causality, and budgets.
The request and response parsers require an integer schema version, not a
Boolean value that compares equal to one in Python.

## Webhook subscription

`WebhookSubscription` binds the tenant and principal to:

- an opaque `endpointref:` value instead of a URL;
- an opaque `secretref:` signing-key value instead of key material;
- a closed, sorted set of event filters;
- a maximum in-flight delivery count;
- a detached signature declaration.

The subscription digest covers all unsigned subscription fields. Cryptographic
signature generation and verification remain responsibilities of an external key
service. This module verifies structural binding and key-reference consistency.

## Delivery, retries, and dead letters

`WebhookDelivery` binds one event and one content-addressed resource to the exact
subscription digest. Each delivery includes a subscription-local sequence number,
unique nonce, occurrence time, expiry time, attempt count, bounded retry plan,
detached signature, and content hash.

`RetryPlan` is metadata only. It records strictly increasing delays and a terminal
attempt count. It has no timer and performs no retries. A delivery can be marked
`dead_lettered` only at the terminal attempt. A delivery cannot mark itself
acknowledged. A separate signed `WebhookAcknowledgement` must bind the exact
delivery ID, digest, and sequence.

`verify_webhook_acknowledgement` also requires the delivery's subscription digest
to match the supplied subscription. Reusing a subscription ID with changed
contents cannot carry an old acknowledgement into the new subscription. This
check verifies declared record bindings only. It does not verify signatures,
apply receiver event filters, accept a delivery, or update replay state.

## Replay protection

`ReplayWindow` is immutable receiver state. `accept_webhook_delivery` performs a
pure validation and returns a new window. It requires:

- exact subscription ID and subscription digest binding;
- an event allowed by the subscription filter;
- the subscription signing-key reference;
- the next contiguous sequence number;
- a previously unseen delivery ID and nonce;
- receipt no later than the declared expiry.

The function does not persist state, verify the detached signature with a key,
acknowledge the delivery, or contact an endpoint. A receiver must persist the new
window atomically before it acknowledges a delivery.

## Integrity and validation

Every top-level contract uses deterministic printable-ASCII JSON and SHA-256
content hashes. Parsers require exact field sets and reconstruct the value to
verify its identity. `ApiRequestEnvelope.from_json` also rejects noncanonical JSON.

`registry/schemas/api-service-contract-v1.schema.json` is a closed Draft 2020-12
schema for all five published top-level representations. Schema validation does
not recompute hashes, compare cross-document bindings, verify signatures, enforce
budget relationships, or update replay state. Consumers must run the matching
runtime parser and the cross-document verification functions as well.

## Infrastructure still required

Production use needs separately reviewed infrastructure for TLS termination,
authentication, tenant isolation, authorization, rate limiting, idempotency and
resource-version storage, cursor issuance, request persistence, audit logging,
key management, detached-signature verification, webhook dispatch, retry timing,
dead-letter storage, replay-window persistence, monitoring, and incident response.
None of those components are implied by these contracts.
