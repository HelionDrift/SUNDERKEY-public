# AI and Protocol Specialist Contracts

`sunderkey.ai_protocol_specialist_contracts` defines a repository-only
assessment boundary for six specialist families:

- AI and LLM applications
- agent protocols
- tool authorization boundaries
- retrieval and grounding systems
- model supply chains
- machine-to-machine protocols

The module provides deterministic capability declarations, assessment
requests, adapter observations, and receipts. It does not contain a provider
client, prompt attack library, model runner, tool executor, network client,
credential resolver, model artifact loader, or autonomous execution loop.

## Capability coverage

The declaration catalog covers eight validation scenarios:

- prompt and context boundary validation
- tool authorization checks
- retrieval provenance tests
- indirect-instruction resistance scenarios
- agent identity and delegation checks
- model artifact provenance
- protocol state validation
- data-boundary leakage controls

Each family declares only the scenarios it can assess. A request for a
scenario outside its declared family fails before adapter invocation.

## Exact context binding

Every request binds the following opaque values and content digests:

- tenant and assessment context
- authorized scope
- model identity or artifact
- tool policy
- retrieval corpus
- session
- agent identity
- delegation chain
- protocol and protocol state
- evidence plan
- action-admission decision
- request, byte, token, and duration budget

The dispatcher compares the complete request context with an independently
supplied expected context. A stale, replayed, tampered, or cross-context
request fails before the injected adapter is called.

## Safe synthetic fixture rule

Requests can reference only a fixture manifest classified by the record as
synthetic and free of real credentials, live target data, and harmful payload
bodies. The request carries an opaque fixture reference and digests, not the
fixture body. Raw prompts, retrieved documents, credentials, executable tool
arguments, model weights, and protocol frames are not contract fields.

This rule supports deterministic control testing without creating a payload
library or transporting sensitive material through the orchestration record.

## Injected adapter boundary

The dispatcher invokes one caller-supplied adapter only after validating the
declaration, full context, active time window, replay sets, idempotency key,
and estimates. The adapter receives the validated request but has no built-in
implementation in this module.

An observation is accepted only when it proves that no network call, provider
call, model execution, or tool execution occurred. It must also report that no
raw secret or live target data was observed. Incorrect request, context, or
fixture bindings and any budget overrun fail closed.

## Findings and evidence

An adapter can report `pass`, `control_gap`, or `inconclusive`. These outcomes
describe the synthetic control assessment and do not authorize target action.
Evidence remains digest-only. The deterministic receipt binds the request,
declaration, context, fixture, observation, and idempotency digest.

## Qualification status

All records set `qualification_effect` to `none`. This increment is
repository-only and nonqualified. Production assessment still requires
separately approved adapters, safe fixture custody, durable replay storage,
live action admission, provider and tool isolation, model and corpus custody,
transport enforcement, evidence custody, operator controls, and independent
qualification.
