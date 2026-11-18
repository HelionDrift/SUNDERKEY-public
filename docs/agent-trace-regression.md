# Offline agent trace regression comparison

`sunderkey.agent_trace_regression` compares two redacted agent-trace reviews
only after reproducing each review from its exact source trace. Both traces
must bind the same tenant, scope, case, and tool policy. The current trace
must have a later observation time and assert a distinct source digest.

The comparison reports issue-code counts that are newly observed or no
longer observed, plus review-status and tool-execution-count changes. Event
sequence numbers are deliberately excluded from issue matching because they
can shift when the trace contains more or fewer events. The result is
content-addressed and can be reproduced from all four inputs.

Each source review and the comparison use exact typed JSON reproduction.
Numeric type substitutions and non-JSON containers cannot retain validity under
an unchanged digest or enter a dependent comparison. Key reordering remains
valid. Comparison input is bounded to 1,000,000 canonical bytes, 24 nesting
levels, and 100,000 nodes; existing valid content addresses remain unchanged.

```sh
python -m sunderkey.cli agent-trace-regression \
  --prior-trace prior-trace.json --prior-review prior-review.json \
  --current-trace current-trace.json --current-review current-review.json \
  > comparison.json

python -m sunderkey.cli agent-trace-regression-verify \
  --prior-trace prior-trace.json --prior-review prior-review.json \
  --current-trace current-trace.json --current-review current-review.json \
  --comparison comparison.json
```

An issue no longer observed in caller-supplied metadata is not a verified
fix. A newly observed issue is not proof of a live regression. Source-trace
custody, external human authority, target authorization, and independent
review remain separate requirements. This command performs no model, tool,
provider, network, or target operation and has no qualification effect.
