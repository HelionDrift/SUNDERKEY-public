# Offline cross-task claim graph

`offline_collaboration_claim_graph.py` composes up to four separately replayed
offline specialist relation reports. It addresses selected premise or hypothesis
statuses in a bounded conjunction graph. This is a review aid for multiple
specialists, not a pathway finder, finding, action plan, or authority source.

Every source context supplies its original relation plan, original task model,
task result, and relation result. The graph replays the relation report, which
replays the task against the current component catalog and leaf sources. Its
verification function repeats that derivation and compares the complete graph,
not only the graph digest. Two source labels cannot count the same task result
twice. Current replay can fail after source drift; a historical graph address
does not establish currentness.

The graph model has exact fields `schema_version`, `graph_label`, `sources`,
`scope_bindings`, `claims`, and `hypotheses`. Each source has an ID. A scope
binding names exactly the sources used by its claims and has the exact basis
`caller_declared_unverified`. A claim selects one premise or hypothesis from one
source and one declared scope. A hypothesis depends on claims or other
hypotheses in that same scope. Unknown and contradiction propagate, with
contradiction taking precedence over unknown. Missing selectors, duplicate
references, cycles, cross-scope dependencies, incomplete bindings, and reused
task evidence fail closed.

This contract deliberately does not infer that two tasks describe the same
target, tenant, network, identity, time, or evidence authority. Even a matching
cross-task conjunction only matches caller-declared expectations under supplied
partial predicates. `scope_equivalence_proven`, `source_authenticated`,
`full_candidate_assembled`, `positive_use_approved`, and
`qualification_claimed` stay false. All operational effects stay `none`.

The model and result use exact native JSON, with a 256 KiB canonical limit,
16,384-node limit, depth 16, scalar text limit 512, signed 64-bit integers,
and no floats, subclasses, cycles, or lone Unicode surrogates. The graph
limits sources to four, claims to 32, hypotheses to 16, and dependency
references to 64. Each inherited relation and task replay keeps its separate
existing budget. These are software bounds, not arbitrary Python isolation.

The interface is intentionally local and explicit:

```python
from sunderkey.offline_collaboration_claim_graph import (
    analyze_offline_collaboration_claim_graph,
    verify_offline_collaboration_claim_graph,
)

report = analyze_offline_collaboration_claim_graph(
    model,
    source_contexts=source_contexts,
    catalog=current_catalog,
    repository_root=repository_root,
)
verified = verify_offline_collaboration_claim_graph(
    report,
    model=model,
    source_contexts=source_contexts,
    catalog=current_catalog,
    repository_root=repository_root,
)
```

Each `source_contexts[source_id]` has exact keys `relation_report`,
`relation_model`, `task_report`, and `task_model`. The result stores source and
task bindings, selected statuses, component and leaf addresses where a premise
was selected, scope declarations, limitations, effects, and a content address.
It does not embed the full unsanitized original source objects and is not a
safe-publication or redaction format. No provider, credential, network, target,
process, deployment, or qualification action occurs.
