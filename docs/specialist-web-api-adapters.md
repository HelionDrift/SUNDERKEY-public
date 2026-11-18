# Web, API, and authentication specialist adapter contracts

`sunderkey.specialist_web_api_adapters` defines a repository-only execution
boundary for roadmap packages A2.5 through A2.11. It supplies deterministic
requests, injected adapter observations, receipts, specialist capability
declarations, and a process-local replay guard. It does not supply a network
client, proxy, browser, scanner, credential resolver, offensive tool, or
exploit implementation.

## Specialist families

The declaration set covers these roadmap packages:

- A2.5 HTTP protocol specialist, including request construction plus proxy,
  cache, and parser boundaries.
- A2.6 authentication specialist, including login, sessions, refresh, logout,
  multifactor checkpoints, and recovery boundaries.
- A2.7 OAuth and federation specialist, including redirect, claim, audience,
  scope, exchange, and federation boundaries.
- A2.8 authorization specialist, including object, function, field, tenant,
  and role boundaries.
- A2.9 business logic specialist, including state, ordering, limits,
  concurrency, and workflow invariants.
- A2.10 API technology specialist, including REST, GraphQL, asynchronous APIs,
  file boundaries, and serialization.
- A2.11 input and service interaction specialist, including parser, template,
  injection, SSRF, deserialization, and downstream service boundaries.

Each operation has a fixed family, package, minimum action tier, authenticated
session requirement, and minimum principal count. The declaration records are
explicitly `repository_only` and `not_qualified`.

## Bound request

A `SpecialistActionRequest` binds the tenant, mission, signed scope, target,
worker, admitted action, specialist operation, action tier, exact approval,
authenticated sessions, required evidence, tool input, idempotency key, and
budget. Tool input is represented by an opaque `toolref:` plus a SHA-256
digest. There is no request field for a password, token, cookie value, payload,
command, or exploit text.

Every R1 or R2 operation requires an exact approval. The approval must bind the
same context and operation, allow the requested tier, and be current when the
adapter is called. Authentication, OAuth, authorization, and business logic
operations require current authenticated session bindings. Authorization
operations require at least two isolated principals. Duplicate principal or
session references fail closed.

## Injected adapter and receipt

`SpecialistExecutionAdapter` is a runtime-checkable protocol with an immutable
adapter identity and one `execute` method. Callers provide the implementation.
`execute_specialist_action` performs all repository-side validation before
calling it. An adapter must explicitly declare the requested operation.

The returned `AdapterObservation` must repeat the exact request ID, request
hash, context hash, and idempotency key. The observation contains only state,
bounded counts, evidence references, evidence digests, and time. Substitution
fails closed. The final `SpecialistActionReceipt` is content addressed and can
be parsed with runtime integrity checks.

## Replay and budget controls

`SpecialistReplayGuard` reserves each idempotency key before adapter execution.
Any second use is rejected without a second call. Production infrastructure
must replace this process-local guard with durable atomic storage while
preserving its no-replay behavior.

The request limits operation count, request bytes, response bytes, evidence
count, and redirects. Observations above any ceiling fail closed. Required
request evidence must remain present in the observation.

## Remaining infrastructure

This increment does not make A2.5 through A2.11 operational or qualified. Live
use still requires separately authorized transports, specialist tools,
credential brokering, durable replay and budget accounting, target session
infrastructure, egress enforcement, monitoring, evidence storage, cleanup,
independent validation, and approved targets. These contracts only define the
boundary those components must satisfy.
