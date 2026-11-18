# Offline collaboration claim delta

`offline_collaboration_claim_delta.py` compares selected hypothesis statuses
from two separately replayed [cross-task claim graphs](offline-collaboration-claim-graph.md).
Each graph must be supplied with its original model and every separate
original task and relation source. Both graphs are rebuilt against the current
specialist catalog before the comparison. Reusing the same underlying graph
evidence under different labels is refused.

The caller supplies exactly two graph sources and one to sixteen pairs of
selected hypotheses. Each pair has a subject label whose binding must be
`caller_declared_unverified`. The output distinguishes
`same_declared_status`, `changed_declared_status`, and `unassessed`. Either
unassessed side yields `unassessed`, even if the other side matches or
contradicts. The packet retains each selected graph address, declared scope,
dependencies, and status. Its verifier reconstructs the entire packet from
current original sources, not merely from the packet digest.

Before and after are caller labels, not trusted chronology. Matching subject
or scope labels do not prove a shared target, tenant, or identity. A status
change can reflect different supplied data or graph definitions. It is not
improvement, regression, a finding, a verified pathway, or authorization.
The bounded, content-addressed packet is unsigned and has no qualification,
publication, routing, execution, credential, network, provider, deployment,
or target effect.
