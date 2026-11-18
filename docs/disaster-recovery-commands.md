# Disaster recovery command adapters

This module turns the repository-only disaster recovery proof contracts into strict commands for an injected backend. It supplies the boundary needed to connect a future backup system or rehearsal environment without placing a process runner, filesystem crawler, socket client, cloud SDK, credential resolver, or database client in the core package.

The implementation supports five command kinds:

1. `create_backup`
2. `verify_backup`
3. `rehearse_restore`
4. `verify_restore`
5. `cleanup_rehearsal`

Every request binds the exact tenant, system, system version, authorized scope, recovery objective, backup manifest, rehearsal plan, backend identity and version, authorization, operator, approver, idempotency key, execution budget, isolation proof, coordinator fence, cleanup obligation, preflight evidence, and active time window. The source objective, manifest, and plan must be canonical and must agree on tenant, system, objective identity, and manifest identity.

## Safety boundary

Restore commands can address only a caller-proven `rehearsalref` destination. The isolation class must be `ephemeral_rehearsal`, network mode must be `isolated`, and `production_destination` must be false. Cleanup and proof of destination absence are mandatory. The operator and approver must be different principals.

A failed preflight returns `blocked_preflight` without invoking the backend. A passing preflight allows exactly one call through `DisasterRecoveryCommandBackend`. The core module has no alternate execution route.

## Outcome model

The adapter preserves these outcomes without collapsing them:

| Outcome | Meaning |
| --- | --- |
| `completed` | The supplied backend result says the requested command completed. |
| `retryable_failure` | The supplied backend result identifies a condition that may be retried under a new authorized execution decision. |
| `terminal_failure` | The supplied backend result identifies a non-retryable failure. |
| `partial_cleanup` | The supplied backend result says cleanup did not fully complete. |
| `blocked_preflight` | Local request preflight evidence blocked execution before any backend call. |

The observation and receipt copy backup, restore, recovery objective, and cleanup flags only from the supplied backend result. They identify the claim source as `supplied_backend_result`. These flags are not independently verified facts. A blocked preflight sets all operational observation flags to false and identifies `request_preflight` as the source.

No command receipt changes qualification state. `qualification_effect` is always `none`.

## Integrity and replay controls

Requests, observations, and receipts use canonical ASCII JSON and content-derived identifiers. Parsers reject unknown fields and altered content addresses. Backend results must echo the exact request identifier, request digest, backend identity, backend version, and idempotency key. The request binds one backend call, bounded runtime, byte and object limits, an exact fence epoch, and an expiration no later than the authorization expiration.

The idempotency key is part of the request content address and is passed unchanged to the backend. The injected backend remains responsible for durable replay suppression. A future backend conformance suite should demonstrate that repeated delivery of the same key does not repeat side effects.

## Infrastructure still required

Repository tests prove deterministic construction, strict parsing, source-contract compatibility, fail-closed validation, and injected boundary behavior. They do not prove that a backup exists, a restore occurred, a cleanup completed, or recovery objectives passed. Those claims require an authorized backend implementation, an isolated rehearsal destination, external custody evidence, and independent review of the resulting observations.
