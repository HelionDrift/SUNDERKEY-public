# Evaluation Runner Contracts

This repository-only increment defines a unified composition contract for
evaluation runner roadmap package E3.4. It turns separately governed inputs
and externally produced observations into deterministic plans, evidence
manifests, aggregate observations, review assessments, and comparison inputs.
It does not execute an evaluation or claim operational qualification.

## Exact run context

Every run plan binds an exact identifier, immutable version, and SHA-256 digest
for each of these components:

1. candidate
2. model
3. provider
4. tool
5. prompt
6. policy
7. corpus
8. range
9. scoring
10. budget
11. custody

Moving versions such as `latest`, `main`, and `head` are rejected. The complete
binding list must occur in canonical order. A plan also binds its case
assignments, assignment evaluators, immutable case digests, fixed membership
digest, replay epoch, and idempotency key.

The plan includes a clean contamination attestation with an exact scanner
version, report digest, timestamp, candidate digest, and corpus digest. The
candidate and corpus digests must equal their corresponding plan bindings.
Any contaminated status, changed report, or cross-context digest blocks the
plan.

The candidate owner, corpus custodian, ground-truth custodian, execution
controller, plan author, and at least two independent reviewers are separate
identities. Execution evaluators are also distinct from all of those roles.
Every case assignment names one of the bound evaluators. Completion reviews
come from the separate reviewer set.

## Fixed denominator

Case membership is committed before any external execution. Results must cover
that exact set once each. Missing cases, duplicate cases, duplicate result
identities, repeated idempotency keys, and replayed nonces fail closed. Failed
and abstained cases remain in the denominator. No result can be imported from
another plan, replay epoch, case digest, assignment, or evaluator context.

An evidence manifest contains a sorted, unique, content-addressed list with
media type and byte size. Result envelopes bind the exact evidence manifest,
status, hard failure codes, usage, timestamp, and plan context. Envelope import
recomputes the content identity and rejects any changed field.

## Budgets and safety

The aggregate enforces hard ceilings for cost in micro-US dollars, latency,
requests, tokens, and tool calls. It counts completed, failed, abstained, and
safety-failure results across the full denominator.

A safety failure must name at least one hard failure code. Hard safety failures
produce a terminal completion assessment and cannot be averaged away by other
successful cases. They remain visible even when every case and review is
otherwise present.

## Independent review and comparisons

Completion requires two distinct, assigned reviewers whose attestations bind
the exact aggregate observation. Missing, duplicate, unassigned, cross-context,
or rejecting reviews fail closed.

Comparison input requires candidate, deterministic baseline, generalist
baseline, and prior-release observations in canonical order. All four must bind
the same fixed case membership, corpus, policy, scoring rules, and budget. Each
reference also binds the identity, digest, and ready status of its completion
assessment. Incomplete, rejected, or hard-failure observations cannot enter a
comparison. The comparison input does not score, rank, route, or qualify any
candidate.

## Non-executing boundary

Every serializable document declares these effects as `none`:

- authorization
- corpus access
- evaluation execution
- model calls
- network activity
- provider calls
- qualification
- range actions
- tool calls

The module contains no provider, model, tool, network, range, or corpus client.
`ready_for_separate_execution` is a structural planning state only. An external
system must separately authorize and perform all operational work.

The strict JSON Schema validates each supported document family. Python parsing
also recomputes content identities and enforces cross-record invariants that a
portable schema cannot express.
