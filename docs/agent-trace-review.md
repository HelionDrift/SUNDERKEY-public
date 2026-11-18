# Offline agent trace review

`sunderkey.agent_trace_review` checks a caller-supplied, redacted agent trace
against a narrow tool-use policy. It is a deterministic review aid for the
V9.12 AI and agent control-validation track. It does not run an agent, model,
provider, target, or tool.

The published [JSON Schema](../registry/schemas/agent-trace-review-input-v1.schema.json)
describes the wire shape. The Python evaluator also enforces timestamp order,
sequential numbering, sorted tool policy, and event-kind-specific fields.

Source and review artifacts must be bounded exact JSON trees. Verification
compares type-preserving canonical bytes, not Python value equality. Boolean,
integer, and floating-point substitutions fail even when Python considers them
equal. Custom containers, non-JSON values, nonfinite numbers, cycles, and inputs
deeper than 24 levels, exceeding 100,000 nodes, or larger than 1,000,000 canonical
bytes are rejected.
Object key order is immaterial; list order and valid artifact digests are unchanged.

The input JSON has exactly these top-level fields:

| Field | Meaning |
| --- | --- |
| `schema_version` | `1` |
| `tenant_ref`, `case_ref` | Opaque `tenantref:` and `caseref:` identifiers |
| `scope_sha256` | Digest of the caller's scope record |
| `source_trace_sha256` | Caller-asserted digest of the source trace |
| `observed_at` | Canonical UTC cutoff for all events |
| `policy` | Sorted unique `allowed_tool_refs` and `maximum_tool_executions` |
| `events` | Up to 256 sequential redacted metadata events |

Each event has `sequence`, `observed_at`, `kind`, `actor`, `action_ref`,
`tool_ref`, and `event_sha256`. The action and tool references must be opaque
for action events and null for other events. Event kinds are `model_call`,
`tool_proposal`, `approval_assertion`, `guardrail_block`, `tool_execution`,
`handoff`, and `final_response`. The contract rejects extra fields, including
raw prompts, model output, tool arguments, credentials, and target content.

The evaluator flags orphan, duplicate, blocked, unapproved, self-approved,
out-of-policy, and over-budget tool execution. A missing final response is
inconclusive, not a pass. The review is content-addressed and can be
reproduced against the exact trace file:

```sh
python -m sunderkey.cli agent-trace-review --trace redacted-trace.json > review.json
python -m sunderkey.cli agent-trace-review-verify \
  --trace redacted-trace.json --review review.json
```

An `approval_assertion` with actor `human` is only a claim in the supplied
trace. This module does not authenticate that person, validate an external
authorization record, verify the source trace's custody, or prove that no
unrecorded events occurred. Even `trace_consistent_for_review` is not a
qualified safety verdict or permission to execute. Live validation needs
authorized target profiles, trusted trace custody, isolated adapters,
independent scoring, and human review before it can make stronger claims.
