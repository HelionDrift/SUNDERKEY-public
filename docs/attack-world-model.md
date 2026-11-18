# Attack world model and evidence graph

`sunderkey.attack_world_model` is a deterministic, infrastructure-independent
planning boundary. It represents what an assessment knows, does not know, and
has evidence against. It performs no network access, tool execution, routing,
qualification, authority change, or deployment.

## Snapshot contract

An attack world snapshot is immutable and content-addressed. Its SHA-256 digest
covers the schema version, parent digest, limits, canonically ordered facts,
derived conflicts, summary, and no-effect declaration. The snapshot ID is
derived from the same digest. Loading a serialized snapshot recomputes the full
document and rejects changed content, changed summaries, unknown fields, and
noncanonical ordering.

Root snapshots have a null `parent_sha256`. Applying an observation delta
creates a new snapshot whose `parent_sha256` is the exact digest of its parent.
The parent is not modified. Deltas are append-only, bounded by
`max_delta_facts`, and cannot redefine an existing node ID or edge fact ID.

The published closed JSON Schema is
`registry/schemas/attack-world-model-v1.schema.json`.

## Typed facts

Node facts use these types:

* `asset`
* `principal`
* `identity`
* `endpoint`
* `service`
* `data_store`
* `finding`
* `control`
* `credential`
* `trust_zone`

Directed edge facts use these relation types:

* `observed`
* `asserted`
* `inferred`
* `reachable`
* `authenticated_as`
* `authorized_to`
* `contains`
* `depends_on`
* `communicates_with`
* `mitigated_by`

Every node and edge has an `EvidenceBinding` with:

* a SHA-256 provenance artifact digest
* a second-precision UTC observation time
* confidence from 0 through 1
* `verified`, `negative`, `hypothesis`, or `abstained` state
* a lowercase source-kind token
* an optional second-precision UTC expiry after the observation time

Evidence contains the digest of an independently retained artifact, not the
artifact bytes. This keeps the model small and makes provenance substitution
detectable when a snapshot is verified.

Credential nodes require an opaque `credref:` reference. The model has no field
for a credential value. Closed parsing rejects added fields, and constructors
reject common secret forms in all caller-controlled text. A credential vault or
secret resolver is deliberately outside this boundary.

## Conflict and time semantics

Positive and negative edge facts conflict when they describe the same source,
relation, target, scope references, and technique references. Conflict records
are deterministic and are stored in the snapshot. Queries can also recompute
conflicts at an explicit `as_of` time so expired facts are ignored.

An active negative fact suppresses a matching hypothesis. It cannot be replaced
or erased by that hypothesis. A fresh verified-positive and negative pair is
also suppressed from path traversal until later evidence resolves the claim in
a new model design or the older evidence expires. Both original facts remain in
the immutable snapshot.

A fact is stale when `expires_at` is equal to or earlier than the query time.
Stale facts do not support candidate paths. They appear as uncovered frontier
items so a later scheduler can request new evidence. The caller supplies all
times. The module never reads a wall clock, so identical inputs remain identical.

## Bounded path queries

`query_candidate_attack_paths` performs breadth-first directed traversal with
canonical neighbor ordering. A node can appear only once in a candidate path,
which makes cycles safe. Snapshot limits bound path depth, edge expansions, and
returned paths. A result reports `truncated: true` when its expansion or path
budget stops the search.

Required scope references must be present on every traversed node and edge.
Required technique references must be covered by the union of edge techniques
in a completed path. Stale, abstained, negative, and conflicted facts do not
become traversal edges.

Results are divided into `verified_paths` and `hypothesis_paths`. A verified path
contains only verified node and edge evidence. Any hypothesis node or edge puts
the path in the hypothesis collection. The path confidence is the lowest
confidence among all facts in that path.

## Uncovered frontier

`compute_uncovered_frontier` reports deterministic, content-addressed gaps for
later scheduling. It can identify:

* required techniques with no active positive evidence
* techniques supported only by hypothesis evidence
* active negative evidence without verification
* stale facts
* evidence conflicts
* targets with no verified path or only a hypothesis path

Frontier output is descriptive. It does not create work, select an expert, grant
authority, or activate an assessment.

## Offline API example

```python
from sunderkey.attack_world_model import (
    AttackEdge,
    AttackNode,
    EvidenceBinding,
    build_attack_world_snapshot,
    query_candidate_attack_paths,
)

evidence = EvidenceBinding(
    provenance_artifact_digest="sha256:" + "a" * 64,
    observed_at="2026-09-19T12:00:00Z",
    confidence=0.9,
    verification_state="verified",
    source_kind="artifact",
)

nodes = (
    AttackNode(
        node_id="asset:start",
        node_kind="asset",
        label="Starting asset",
        scope_refs=("scope:assessment",),
        technique_refs=(),
        evidence=evidence,
    ),
    AttackNode(
        node_id="service:target",
        node_kind="service",
        label="Target service",
        scope_refs=("scope:assessment",),
        technique_refs=(),
        evidence=evidence,
    ),
)

edges = (
    AttackEdge(
        fact_id="fact:reachable",
        source_node_id="asset:start",
        target_node_id="service:target",
        edge_kind="reachable",
        scope_refs=("scope:assessment",),
        technique_refs=("technique:access",),
        evidence=evidence,
    ),
)

snapshot = build_attack_world_snapshot(nodes, edges)
result = query_candidate_attack_paths(
    snapshot,
    start_node_ids=("asset:start",),
    target_node_ids=("service:target",),
    required_scope_refs=("scope:assessment",),
    required_technique_refs=("technique:access",),
    as_of="2026-09-20T12:00:00Z",
)
```

All snapshot, query, and frontier serializations declare `authority`,
`qualification`, `routing`, and `deployment` effects as `none`.
