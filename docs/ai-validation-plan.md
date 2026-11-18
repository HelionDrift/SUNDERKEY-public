# Offline AI Validation Plan

This V9.12 planning component accepts only opaque metadata for an asserted
synthetic or nonproduction AI target and a bounded adversarial case set. It
does not load prompts, call a model, invoke a tool, contact a target, or grant
authorization. A content-addressed plan can be reproduced from the exact
profile and case inputs with `verify_ai_validation_plan`.

## Target Profile

A profile declares one tenant, scope digest, target reference and class,
environment, owner reference, authorization source digest, system revision,
redaction policy digest, and a seven-day maximum window. It inventories at
most 32 opaque tool references, with no tools allowed for a model-only target.
Request and token ceilings, a 0 to 30 day retention declaration, and all
three mandatory stop rules are required. These fields are caller assertions.
They do not prove target ownership, identity, authorization, storage behavior,
or enforcement of a stop condition.

## Threat Cases And Review

Up to 32 cases may reference an opaque prompt fixture and scoring rubric by
digest. The closed threat classes cover prompt injection, data leakage,
jailbreaks, tool boundaries, agent delegation, and MCP trust. Each class has
an exact expected and prohibited behavior pair. Tool-dependent classes
require inventoried tool references. Per-case ceilings must fit the profile's
aggregate limits. Raw prompt content, model output, endpoint URLs, credentials,
tool arguments, and executable payloads are outside the contract.

Each case names a proposed reviewer, but reviewer identity and independence
remain unverified. A critical verdict needs independent human review and
correlated evidence, not a model judge alone. This plan cannot score a case or
establish a live regression. Existing
[agent trace review](agent-trace-review.md) and
[trace regression comparison](agent-trace-regression.md) handle separate
caller-supplied redacted observations without promoting this plan into run
authority. The output schema is
[`ai-validation-plan-v1.schema.json`](../registry/schemas/ai-validation-plan-v1.schema.json).

Before any nonproduction run, separate controls must authenticate the owner
and target, verify exact scope, isolate adapters and prompt custody, enforce
budgets and stop rules, provide trusted traces, and arrange independent
scoring. Production or customer testing needs its own authority and approval
chain. This offline plan has no model-call, network, target, or tool effect.
