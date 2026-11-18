# Operator Console Client

Status: repository-only contract implementation for WQ-008 and capability
package P5.3.

## Purpose

The operator console client turns verified `operator_projection` records from
the local API contract into a deliberate plain-text console view. It also
creates content-addressed interaction receipts and can prepare an
`OperatorIntentRequest` when the displayed projection advertises that intent.

The console is designed for keyboard and screen-reader workflows. State and
health are always stated in text. Headings establish a stable reading order.
Empty collections, empty result pages, errors, redacted sections, and external
authorization requirements all have explicit text. Rendering never relies on
color.

## Boundary

`OperatorConsoleClient` accepts an injected `OperatorConsoleTransport`. The
transport receives a `local_api_service.ServiceRequest` and returns a
`ServiceResponse`. The client only creates `get_resource` and `list_resources`
requests for `operator_projection` resources.

The client does not:

- open a socket or select a network endpoint;
- authenticate a principal or access credentials;
- grant authorization;
- persist a request, response, receipt, or projection;
- publish or execute an operator intent;
- mutate a mission, worker, asset, finding, or approval;
- claim deployment or production readiness.

Authentication, authorization, transport effects, and persistence belong to
separate injected components. A prepared intent remains a no-effect request
object with `authorization_status` set to `external_required`.

## Projection record contract

The resource payload consumed by this client is the complete canonical object
returned by `OperatorConsoleProjection.to_dict()`. The local API resource ID
must equal the projection ID. The record must also match the requesting tenant
and context.

The client verifies all of the following before rendering:

1. Response request ID and request digest match the issued request.
2. The response reports a newly completed read and no mutation effect.
3. List items are unique and strictly ordered by resource ID.
4. The resource kind, tenant, and context match the request; a get also returns
   exactly the requested resource identifier, not another valid projection.
5. The resource payload digest is valid.
6. The projection envelope and content address are valid.
7. The projection view role matches the client role.
8. Every string that can reach the terminal uses printable ASCII with no
   terminal control characters.

A publisher or persistence adapter must materialize the complete projection
payload in this read model. This client does not change the current local API
mutation contract and does not publish that read model itself.

## Pagination and replay controls

Callers supply a fresh request ID and canonical UTC timestamp for each read.
List calls also supply a page size from 1 through 100 and may supply the opaque
cursor returned by the prior page. The client binds the cursor, requested page
size, returned item identities, response digest, tenant, context, principal,
and role into the interaction receipt.

One client instance consumes each request ID once, including failed attempts.
It rejects replay-status responses, response rebinding, unordered pages,
duplicate projections, cross-context records, mixed roles, and empty pages
that advertise another cursor.

## Interaction receipt

`OperatorConsoleInteractionReceipt` records only verified metadata:

- request and response content digests;
- tenant, context, principal, role, operation, and timestamp bindings;
- input and output pagination bindings;
- authorization decision references returned by the service;
- resource version, concurrency token, payload digest, projection identity,
  and assessment version for every item;
- an explicit no-effect envelope.

The receipt ID and digest are derived from canonical JSON under a versioned
domain. `parse_operator_console_receipt()` accepts canonical JSON only,
requires exact fields, recomputes the identity, and rejects tampering.
The schema is
`registry/schemas/operator-console-client-receipt-v1.schema.json`.

## Rendering states

`render_projection()` creates one deterministic text view. It uses textual
state and health labels, counts, section headings, explicit empty messages,
and a final redaction statement.

`render_empty_state()` explains that no verified projection is available and
suggests checking tenant and context selection before using a new request ID.

`render_error_state()` displays a stable error code and does not reflect
untrusted response text. The operator can preserve the interaction material
and retry with a new request ID.

## Intent preparation

`prepare_intent()` accepts only a projection previously verified by the same
client instance. The projection role must still match, and the requested
intent must appear in `available_intents`. The resulting object remains bound
to the assessment version, principal, timestamp, idempotency key, and operator
rationale. Creating it does not authorize, publish, or execute it.

## Verification

Focused tests cover list and get reads, pagination, empty and error rendering,
request and response binding, replay rejection, mutation-effect rejection,
tenant and context isolation, role isolation, malformed payloads, unsafe text,
intent restrictions, receipt round trips, tamper rejection, JSON Schema
validation, and honest capability metadata.
