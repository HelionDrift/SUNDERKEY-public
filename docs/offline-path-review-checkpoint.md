# Supplied Path Review Checkpoint Projection

The GA-D04-S09 partial component replays the bounded
[abstract attack graph](offline-attack-graph-model.md) from a synthetic
original model. It then removes caller-named intermediate review nodes
and checks whether each declared entry-to-objective route still exists.
The checked example is
[`examples/offline-path-review-checkpoint-component.json`](../examples/offline-path-review-checkpoint-component.json).

Supported and hypothesized edges are distinguished. A supported route
that avoids all review nodes is a gap in the supplied graph only. A
hypothesized avoidance or incomplete graph stays uncertain. This is a
graph cut test, not live discovery, proof of a traversable path, or
authorization to follow one. The graph, provenance labels, and review
nodes are all synthetic assertions. Real target identifiers and
operator-supplied graph sources are not accepted by this component.

The result contains base analysis digests and per-pair booleans, not
an operational route or payload. Independent verification replays the
separate original graph and review-node set. No credential, process,
network, target, finding, or qualification effect occurs.
