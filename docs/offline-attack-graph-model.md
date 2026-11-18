# Supplied attack-graph modeling

This R0 partial component belongs to existing specialist `AOE-GA-D01-S11`,
capability `army.ga.d01.s11`, and vector `AV-GA-D01-S11-01`. It contributes
partial offline algorithm evidence only. It does not complete the specialist,
assemble a candidate, qualify one, or authorize live use.

## Bounded input and projection

`analyze_supplied_attack_graph(model)` accepts an exact version 1 abstract
graph with a caller-declared completeness flag, evidence-source labels, nodes,
and directed edges. Node kinds are `entry`, `intermediate`, and `objective`.
Edge relations are `declared_access`, `declared_dependency`, and
`declared_trust`. Edge statuses are `supported`, `hypothesized`, and `blocked`.
These names refer only to caller-supplied declarations. IDs are opaque; the
model accepts no hostname, URL, payload, credential, or executable step.
Every node and edge references a declared evidence source. Provenance kind is
limited to `synthetic_fixture` or `operator_supplied`. A source ID is a label,
not evidence authentication.

For each entry and objective pair, the analyzer finds the shortest supported
path through declared supported edges. If there is no supported path but a
path requires one or more hypothesized edges, the disposition is
`unknown_hypothesized_edge`. Blocked edges are not traversed. If no path is
supplied, a complete graph gives the narrow `no_supplied_path` result; an
incomplete graph gives `unknown_incomplete_graph`. A supported path remains a
supplied-graph reachability result even if the graph is incomplete. Finite
cycles terminate without inventing paths. Multiple declarations are sorted
for stable tie-breaking, and graph, report, and traversal sizes are bounded.

`supplied_supported_reachability` does not assert exploitability, a weakness,
or observed target behavior. Likewise, `no_supplied_path` is not proof that a
real path is absent. The report retains uncertainty and no live vulnerability
verdict.

## Replay and effects

The report retains the supplied model, model SHA-256 address, source IDs, pair
projections, and uncertainty. `AttackGraphModelReport.from_json` checks that a
report replays its retained model, but that alone does not establish that the
retained model is the original source. Consumers must call
`verify_supplied_attack_graph(report, model=original_model)` with the
independently held original model before using the projection as evidence.
The checked synthetic common R0 envelope is
`examples/offline-attack-graph-model-component.json`.

The analyzer performs no network call, target discovery, process execution,
credential resolution, payload generation, finding publication, qualification,
or authority decision.
