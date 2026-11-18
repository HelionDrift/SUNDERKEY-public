# Signed integration events and durable outbox

This contract is an infrastructure-independent boundary for later API, webhook,
ticketing, SIEM, and collaboration adapters. It creates no network connection,
imports no network client, and grants no authority to change assessment or finding
state. External adapters resolve opaque destination references and credentials in a
separate trust domain.

## Safety boundary

An integration event is a projection of a change that already happened. It is not a
command. The allowed event families are asset, assessment, finding, retest, report,
and stop-state changes. Event, destination, and delivery observation documents have
explicit `none` values for every authority and state effect field.

Event bodies contain only:

* Stable subject and aggregate identifiers.
* Previous and current state.
* Normalized severity.
* SHA-256 references to separately held artifacts.
* A short safe summary.
* Opaque link references that must be resolved elsewhere.

Credentials, secrets, raw evidence, exploit payloads, request bodies, response
bodies, and direct URLs are rejected. A destination stores only opaque routing
references. It never stores a token, password, endpoint URL, or vendor response.

## Identity and signatures

`create_integration_event` derives the partition key, ordering key, content digest,
event identifier, and event idempotency key from canonical JSON. Equal inputs create
equal identities. The frozen Python value and the SQLite immutable custody triggers
provide separate mutation defenses.

`sign_integration_event` signs the canonical event envelope with Ed25519. The
envelope records only a key identifier and public key digest. The public key is not
embedded. `verify_integration_event` requires the caller to supply that public key
out of band and returns a `VerifiedIntegrationEvent` capability wrapper.

Delivery observations use the same pattern. The adapter signs an observation that
binds the exact event digest, event signer, destination digest, delivery idempotency
key, and attempt number. Verification rejects key substitution, destination
substitution, event substitution, and attempt substitution. An event signer cannot
sign its own acknowledgement.

Observation production and expected-event verification require the declared
observation time not to precede the full event's declared occurrence time. Equal
times are valid, and fractional instants are compared as UTC times, not text.
This is source consistency, not proof of either timestamp's truth or a shared
clock. Historical signed-document parsing and bare signature inspection do not
receive the full event and do not establish a verified delivery capability.

The JSON Schema at
`registry/schemas/integration-outbox-event-v1.schema.json` describes the signed event
wire document and declares Draft 2020-12.

## Destinations and adapter contract

Four destination forms are accepted:

| Kind | Required opaque route fields |
| --- | --- |
| `generic_webhook` | `endpoint_ref` |
| `jira_ticket` | `project_ref`, `issue_type_ref` |
| `siem` | `stream_ref` |
| `collaboration` | `channel_ref` |

`ExternalDeliveryAdapter.deliver` accepts only a verified signed event and a
`DestinationReference`. The reference has the destination identifier, digest, and
kind, but not its routing fields or credentials. An external adapter returns a
`SignedDeliveryObservation`. `deliver_with_adapter` checks the adapter signature and
all bindings before the observation can enter durable custody.

No vendor client or delivery implementation belongs in this module.

## Durable lifecycle

`IntegrationOutbox` requires an explicit filesystem access controller. The supplied
POSIX implementation verifies owner identity, owner-only modes, file types, and
symbolic-link absence. A platform with different access controls must supply a
controller with equivalent custody properties.

Initialization creates a SQLite database with an application identifier, schema
version, foreign keys, rollback journaling, immutable event and destination tables,
an append-only receipt table, and guarded immutable bindings in the mutable work
projection.

Enqueue is atomic. Event custody, destination custody, and the work entry commit in
one transaction. Repeating an identical enqueue returns the existing record.
Rebinding an event, destination, or idempotency key is rejected.

Claim uses `BEGIN IMMEDIATE` to serialize competing claimers. It selects only due
work and only the earliest nonterminal entry in a partition. Each claim increments
both its attempt count and fencing token. A worker must present the exact worker,
attempt, and fencing values to complete the claim. An expired lease may be claimed
again with a greater fence. Completion under the stale fence fails.

Completion also joins the supplied lease back to the selected durable work row,
the exact signed event envelope, and the exact destination descriptor. Changing a
lease's event, producer signer, destination route, or delivery idempotency binding
cannot attach a foreign acknowledgement to the original work. These joins are
checked in the completion transaction before any receipt is inserted.

Expiry permits reclaim; it does not alone reject terminal settlement under the
same active worker, attempt, and fence. A successor claim, cancellation, or terminal
transition makes the old completion stale. No shared store/adapter clock or
zero-skew rule is inferred from the declared event-to-observation time relationship.

Each claim also resolves the producer public key out of band and verifies the stored
event again. This makes reopening after a process crash independent from any
in-memory verification marker.

A retryable failure uses bounded exponential scheduling. The configured maximum
attempt count and retry timing bounds are persisted with the entry. A permanent
failure, an exhausted retry, or an expired final lease enters `dead_letter`.
Cancellation can revoke pending,
retrying, or leased work. A completion after cancellation is stale and fails.

Every accepted adapter observation is appended before the work state transition.
Unique observation identity and one receipt per attempt prevent replay. A successful
entry cannot accept a second success receipt.

## Delivery guarantee

The outbox provides at-least-once delivery semantics. A process can fail after an
external system accepts a request and before local receipt commit. The lease will
expire and the outbox will offer the same deterministic delivery idempotency key on
the next attempt. Consumers and external adapters must deduplicate using that key.

This contract does not claim exactly-once delivery. Exactly-once behavior cannot be
provided across an external side effect and a local SQLite transaction without a
shared transaction coordinator.

## Minimal flow

1. Build and sign an event.
2. Verify it with a producer public key obtained out of band.
3. Build an opaque destination descriptor.
4. Atomically enqueue the verified event and descriptor.
5. Claim work with an event public key resolver.
6. Give the verified event and destination reference to an external adapter.
7. Verify its signed delivery observation with the adapter public key.
8. Complete the fenced lease with the verified observation.

Application code should retain dead-letter entries and receipts for audit. Replay or
operator tooling can create a new integration event with a new content identity. It
must not mutate or delete prior custody.
