# Durable integration delivery worker

## Purpose

The integration delivery worker implements roadmap item WQ-009. It joins the
durable SQLite integration outbox to generic webhook subscriptions and pinned
enterprise connector bindings. The worker performs bounded delivery attempts
only through a caller-supplied transport.

The implementation provides real local orchestration and durable outbox state
changes. It does not provide an HTTP client, socket access, endpoint discovery,
credential access, secret access, key storage, or a deployed worker service.

## Runtime boundary

`IntegrationWorkerTransport` is the only external delivery boundary. The host
supplies three operations:

- `send` for a pinned enterprise connector request;
- `send_webhook` for a content-addressed generic webhook request;
- `acknowledge` for an Ed25519-signed outbox delivery observation.

The module does not import an HTTP library. Endpoint, signing-key, and
credential values remain opaque references. A transport implementation may
resolve those references outside this module under deployment-specific policy.

## Route binding

Every `WorkerRoute` binds one tenant and one exact outbox destination identity.
A route is one of the following:

| Route | Required contract | Binding checks |
|---|---|---|
| `webhook` | `WebhookSubscription` | Tenant, destination digest, event filter, in-flight ceiling |
| `enterprise_connector` | `ConnectorBinding` | Tenant, destination reference, pinned operation, active interval |

Cross-tenant routes, changed destination digests, inactive connector bindings,
and missing acknowledgement keys fail before delivery.

## Attempt lifecycle

One `run_once` call performs the following bounded sequence:

1. Validate the explicit UTC observation time and all route activity windows.
2. Claim due outbox entries in persisted sequence order with a fencing token.
3. Limit the claim to `WorkerPolicy.claim_limit` and the lease to
   `WorkerPolicy.lease_seconds`.
4. Build a content-addressed request whose expiry is no later than the lease and
   any connector expiry.
5. Call exactly one injected send operation per claimed attempt.
6. Normalize response metadata without storing a response body.
7. Require a separately signed acknowledgement bound to the exact event,
   destination, delivery idempotency key, attempt, adapter, outcome, and remote
   receipt.
8. Complete the fenced lease through `IntegrationOutbox.complete`.
9. Publish one content-addressed `WorkerAttemptReceipt`.

Before either injected send operation, the worker rejects an observation time
earlier than the claimed event's declared occurrence time. A rejected claim remains
leased with no transport call, acknowledgement, or receipt; there is no automatic
retry. The comparison does not assert timestamp truth, a shared store/adapter
clock, or a new completion deadline. Existing same-fence terminal settlement remains
valid when a transport callback crosses lease expiry without reclaim or cancellation.

Transport exceptions do not synthesize success or failure evidence. The lease
remains fenced until it expires. A later worker may reclaim it with a higher
fencing token. This is deliberate at-least-once behavior.

## Retry and dead-letter behavior

Retry counts and backoff parameters are persisted by the outbox at enqueue
time. Retryable transport outcomes use the outbox's bounded exponential
schedule. Permanent failures move directly to `dead_letter`. A retryable
failure on the last allowed attempt also moves to `dead_letter`.

The attempt receipt records the persisted attempt number, maximum attempts,
next attempt time, optional remote retry hint, and final outbox state. The
remote retry hint is evidence only. It cannot shorten or replace the persisted
local retry schedule.

## Idempotency and replay

The outbox delivery idempotency digest remains unchanged across retries.
Generic webhook requests carry that digest directly. Enterprise connector
requests receive a deterministic `idem:` representation of the same digest.
Each attempt request still has a distinct content identity because it includes
the attempt time or attempt number.

Acknowledgements are verified with the route's configured Ed25519 public key.
Substitution of the signer, event, destination, idempotency key, attempt number,
adapter, status, or remote receipt is rejected. The outbox also rejects a
second completion for the same attempt.

## Receipt contract

`WorkerAttemptReceipt` binds:

- worker, tenant, route, destination, and connector identities;
- outbox sequence, fencing token, attempt budget, and lease expiry;
- request, normalized transport observation, response, and acknowledgement
  digests;
- outcome, persisted next-attempt time, retry hint, remote receipt, and error;
- the `at_least_once` delivery semantic; and
- `none` authorization, deployment, and qualification effects.

The receipt explicitly sets `exactly_once_claimed` to `false`. SUNDERKEY does
not claim exactly-once delivery because a remote system can accept a request
before a transport failure prevents acknowledgement. Remote idempotency support
reduces duplication risk but does not change the delivery semantic.

The strict Draft 2020-12 schema is
`registry/schemas/integration-delivery-worker-v1.schema.json`. The schema and
runtime parser reject unknown fields and content-address tampering.

## Remaining deployment work

Infrastructure is still required for:

- a supervised process or service manager;
- concrete HTTP transports and endpoint resolution;
- credential and signing-key custody;
- external endpoint allowlists and egress controls;
- operational metrics, alerting, and dead-letter administration; and
- live interoperability tests against approved webhook, Jira, and Microsoft
  environments.

Those deployment concerns do not change the worker's authorization,
qualification, or target authority. All remain `none`.
