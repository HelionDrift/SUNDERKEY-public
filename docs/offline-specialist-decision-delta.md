# Offline specialist decision delta

`offline_specialist_decision_delta.py` compares selected actual decisions from
two separately replayed [declared evidence relation](offline-specialist-task-relations.md)
reports. It requires both original relation and task models and reports, the
current specialist catalog, and the repository root. Its verifier reconstructs
the entire result from those separate current sources, rather than trusting a
saved digest or the supplied delta packet.

The caller supplies exactly two distinct source labels and one to sixteen
before/after premise pairs. Each pair crosses those sources, names a declared
subject, and explicitly marks its binding `caller_declared_unverified`.
Repeated task evidence and cross-component comparisons are refused. The
comparison is over the selected supplied-flow `actual_decision` fields only.
It yields `same_supplied_decision`, `changed_supplied_decision`, or `unassessed`.
An unassessed side cannot become a claimed change.

Before and after are caller labels, not trusted chronology. Equal subject
labels do not prove that the sources describe the same target, tenant, flow, or
identity. The decisions are partial provider predicates, not observed
reachability. A difference is not an improvement, regression, finding, or
action permission. The bounded, content-addressed packet is unsigned and has
no qualification, publication, execution, routing, credential, network,
provider, or deployment effect. It does not contact a target or provider.
