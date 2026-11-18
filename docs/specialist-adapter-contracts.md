# Specialist Adapter Contracts

`sunderkey.specialist_adapter_contracts` defines a repository-only execution boundary for six specialist assessment families:

- network
- host
- container
- database
- messaging
- lateral movement

The module provides capability declarations and deterministic request and receipt records. It does not provide a network client, remote shell, database driver, message broker client, container runtime client, credential resolver, exploit payload, or autonomous execution loop. A caller-supplied adapter is the only component that can interact with a target.

## Action classes and gates

Each action class has one exact minimum tier:

| Class | Tier | Intended boundary |
|---|---:|---|
| `passive` | R0 | No credential lease and no target change |
| `authenticated_read` | R1 | Opaque credential lease required and no target change |
| `validation` | R2 | Opaque credential lease and explicit approval binding required, with no target change |
| `controlled_change` | R3 | Opaque credential lease, approval, positive change budget, cleanup plan, and restoration plan required |

The implementation contains no exploit payloads. A production adapter may only implement actions separately authorized by the signed scope and must independently enforce the complete request before any effect.

## Exact execution context

Every request binds the following values and their digests where applicable:

- tenant and mission
- signed scope
- exact target
- approved route
- worker and session
- fence reference, epoch, and token digest
- atomic action-admission decision
- approval decision
- opaque credential lease
- evidence plan
- cleanup plan
- restoration plan
- request, byte, change, and duration budgets

Changing any context field changes the context digest and request identity. Dispatch compares the complete request context with an independently supplied expected context. A cross-context request fails before the injected adapter is called.

## Determinism, replay, and budgets

Declarations, requests, and receipts use canonical JSON and content-derived identities. The dispatcher rejects expired or not-yet-active requests, previously seen request identities, and previously seen idempotency digests before adapter invocation. It also rejects requests whose estimates exceed their bound budget.

Adapter observations carry only identifiers, counts, times, and evidence digests. An observation with incorrect request or context bindings is rejected. Reported use beyond request, byte, change, or duration limits is rejected. Non-changing actions cannot report target changes.

## Cleanup and restoration

An R3 controlled change cannot produce a completed receipt unless the adapter supplies both cleanup and restoration completion evidence. A completed adapter observation with incomplete cleanup or restoration is normalized to `halted_cleanup_required`. The record preserves evidence for operator handling but does not claim successful completion.

## Failure behavior

The boundary fails closed for malformed references, raw secret patterns, unknown fields, digest tampering, tier escalation, stale requests, replay, context mismatch, declaration mismatch, observation mismatch, budget overrun, and unapproved changes. No retry occurs in this module.

## Qualification status

These contracts have `qualification_effect` set to `none`. They are repository-only and nonqualified. Production use still requires separately approved adapters, credential custody, target authorization, enforced egress, live action admission, approval services, durable replay storage, budget enforcement at the transport, evidence custody, cleanup workers, restoration verification, operator interfaces, and independent qualification.
