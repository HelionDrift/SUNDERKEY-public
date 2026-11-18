# Offline claim-to-world projection

`offline_claim_world_projection.py` is a bounded, nonqualifying bridge from the
[cross-task claim graph](offline-collaboration-claim-graph.md) into the existing
[attack world model](attack-world-model.md). It requires the graph report,
original graph model, all separate original task and relation inputs, the
current specialist catalog, and the repository root. It replays those sources
before constructing a root world snapshot.

The caller supplies one declared scope, two to sixteen typed nodes, and one
link disposition for every graph hypothesis in that scope. Links cannot cross
to an unknown node or omit a contrary or unassessed hypothesis. Every node
must belong to a link. Credential, finding, and control node kinds are refused.
The plan's `projected_at` and `expires_at` are caller-declared UTC timestamps;
their interval must be positive and no longer than 24 hours. The module does
not read a trusted clock.

Only a graph hypothesis with `matches_declared_expectation` creates an
`inferred` world edge. It has `verification_state=hypothesis` and confidence
`0.0`, as do all projected nodes. Contradictory and unassessed hypotheses are
listed as withheld links. They create neither an edge nor a negative fact.
All facts expire at the declared cutoff. A world query can therefore return a
candidate hypothesis path during the supplied interval, never a verified
path from this projection. Matching supplied premises do not prove network
reachability, a shared target, access, exploitability, or authority.

The content-addressed projection packet binds its exact source model, graph
address, complete world snapshot, withheld links, and fixed no-effect flags.
`verify_offline_claim_world_projection` rederives the complete packet from
separate current originals. An altered graph, model, world fact, status, or
claimed positive-use flag is refused. The packet is not an authenticated
observation, safe publication, finding, assignment, qualification, or
authorization source. It performs no target, provider, network, process,
credential, or deployment action.
