# Execution control runtime

## Purpose

`execution_control_runtime.py` places deterministic, fail-closed controls around a
caller-supplied transport. It covers the documented testing-window,
request-rate, byte-budget, concurrency, and sequential-execution boundary while
remaining usable without external infrastructure.

The runtime does not authorize an operation. Upstream scope, approval, target,
credential, and action-admission controls remain mandatory. The runtime accepts
their exact identifiers and content hashes as bindings and rejects any mismatch.

## Adapter boundary

The module contains no HTTP client, socket access, DNS resolution, credential
discovery, filesystem access, subprocess execution, or target discovery. It can
call only the injected `ExecutionTransport` protocol. Every receipt states
`injected_adapter_boundary_only`; it never claims enforcement by a remote target,
network device, cloud control plane, or service provider.

The other injected protocols are:

- `ExecutionClock`, which supplies a canonical UTC time and a monotonic integer
  tick.
- `ExecutionStateRepository`, which performs atomic lookup, reservation,
  completion, and idempotent outcome storage. Completion releases the
  reservation and stores the outcome in one adapter operation.

An adapter cannot silently weaken the controls. The runtime independently
derives the required reservation and completion transitions and compares them
to the repository observations before treating them as valid.

## Exact binding

Every request and state observation binds all of the following values:

- tenant identifier
- context identifier and content hash
- scope identifier and content hash
- target identifier and content hash
- session identifier
- lease identifier
- fence epoch
- policy identifier and content hash
- payload content hash and exact byte size
- idempotency key
- attempt number and prior execution receipt for retries
- cleanup obligation content hash

Cross-context use, policy rebinding, stale fence epochs, and idempotency-key
rebinding are blocked before transport invocation.

## Admission controls

Admission is allowed only when all checks succeed:

1. The observed UTC time is inside a configured half-open allowed window.
2. UTC time and the caller-supplied monotonic tick advance without rollback.
3. The exact lease is current and the fence epoch matches.
4. Health is `healthy`; `paused` and `unhealthy` fail closed.
5. Cancellation and emergency-stop flags are both clear.
6. The attempt is within the explicit retry budget.
7. A new session fits within the maximum concurrent-session limit.
8. No execution is active when sequential-only mode is selected.
9. The target's request ceiling has capacity.
10. The target's byte ceiling has capacity.
11. The repository returns the exact content-addressed transition that the
    runtime independently derives.

The request limiter supports either a fixed window or an integer token bucket.
The integer token bucket uses only whole refill periods and whole tokens. It
does not use floating-point time or token arithmetic. Byte counters use the same
fixed period boundary and reset only at an exact or later period boundary.

## Idempotency and retries

An exact stored idempotency result is returned without another clock read,
reservation, or transport call. Reusing an idempotency key for different request
content is blocked.

The runtime performs no automatic retry. A failed transport receipt records one
of these dispositions:

- `retry_permitted` when the failure code is explicitly allowed and another
  attempt remains
- `retry_exhausted` when the attempt limit has been reached
- `failure_not_retryable` for any other transport failure

Each caller-created retry must increment its attempt number and bind the prior
execution receipt hash.

## Receipts and failure states

Admission and execution receipts are separately content addressed. A blocked
request has an admission receipt and no execution receipt. A transport failure
has an admitted receipt plus a `transport_failed` execution receipt. A failure
to verify or store post-transport state is reported as `completion_failed`,
because the transport may already have performed an effect. A failed atomic
completion leaves the reservation held, so a sequential policy blocks a later
duplicate instead of silently performing it again.

Cleanup is never marked complete by this runtime. When policy requires cleanup,
the execution receipt records `pending_external_verification`. A separate
restoration workflow must perform and verify the cleanup obligation.

The schema in
`registry/schemas/execution-control-receipt-v1.schema.json` validates both receipt
kinds and rejects unknown properties or an expanded enforcement claim.

## Infrastructure follow-up

Repository-only tests use deterministic in-memory fakes. Deployment still needs
an atomic durable state adapter, an approved monotonic clock source, and a
transport implementation. Those adapters must be tested for transaction
isolation, crash recovery, lease fencing, clock behavior, and target-specific
rate semantics before any external-environment qualification can be claimed.
