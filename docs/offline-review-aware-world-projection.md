# Offline Review-Aware World Projection

`offline_review_aware_world_projection.py` is an opt-in, read-only overlay on
the existing claim-to-world projection. It can remove a zero-confidence
hypothesis edge when the current local review custody contains a challenge or
needs-evidence assertion against that hypothesis or any contributing claim.
It cannot add an edge, increase confidence, change a verification state, or
promote an unsigned review to accepted independent judgment.

## Source Replay and Join

Each projection call first verifies the base world projection from its
separate original graph, task, and relation inputs and current specialist
catalog. It separately replays the review handoff and local review custody
against those same originals. Exact graph, handoff, declared scope, catalog,
and custody head bindings must agree. The derivative packet binds the original
projection digest, handoff digest, local custody head, filtered world snapshot,
and all withheld links. Verification rederives the complete packet from
current originals rather than accepting its public hash alone.

The handoff's contributor list propagates a challenged or needs-evidence claim
to every dependent projected hypothesis. A direct hypothesis assertion has
the same suppressive effect. Contrary or unassessed graph hypotheses remain
withheld by the base projection. A local withdrawal can make the original
hypothesis edge visible again, but only at its prior zero-confidence,
`hypothesis` state. Favorable unsigned assertions never upgrade it.

## Trust and Effect Boundary

Review custody records are unsigned operator assertions. The module does not
authenticate reviewers, producers, tenants, scopes, clocks, source evidence,
or the entire SQLite history against an external anti-rollback anchor. Scope
labels remain caller-declared, and separate source reads are not an atomic
cross-store snapshot. A malicious local assertion could suppress a planning
hypothesis. It cannot make one verified or authorize its use.

Every derivative reports `independent_review_accepted: false`,
`verified_path_created: false`, and `positive_use_approved: false`. All target,
network, credential, execution, routing, publication, assignment, finding,
qualification, and world-edge-promotion effects are `none`. It is not a
finding, proven attack path, production decision, or action credential.

Focused tests:

```text
python -m unittest tests.agents.test_offline_review_aware_world_projection -v
```
