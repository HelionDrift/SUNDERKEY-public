# Offline Action Workspace Link

`link_offline_action_to_workspace` checks one caller-selected admission receipt
against a saved mission action-custody snapshot and a saved composed mission
trace. It is a read-only operator observation. It cannot authorize an action,
declare a current work assignment, or prove a simultaneous cross-store state.

## Exact Historical Origin

The action snapshot's version 3 receipt projection carries the origin
workspace ID and historical digest, plan ID, and reviewed work ID. MissionStore
verified the admission's typed resolution, authenticated proposal import,
review snapshot, closure, and product inside one read transaction. The link
requires those historical origin IDs to match the trace's selected workspace
and plan, and requires the mission revision and head to match both projections.
It never equates the historical review workspace digest with the current
workspace store digest. The trace does not project the current work assignment,
so the link does not claim that the work item remains assigned or complete.

## Recheck and Trust Boundary

The caller must pin tenant, mission, workspace, and receipt IDs independently
of the saved documents. The function requires the mission audit service to use
the same MissionStore and registry objects as action custody. It fresh-verifies
the action snapshot against MissionStore, rechecks the trace against the
MissionStore audit, expert workspace, and orchestration journal, then verifies
the action snapshot again. Any observed source change or exact-identity
mismatch fails closed. It selects one receipt from a snapshot capped at 100
receipts, rather than claiming that every action in the mission came from the
selected workspace.

The returned dictionary is an ephemeral result, not a signed or independently
replayable credential. It reports `cross_store_consistency: not_proven`,
`source_identity_authenticated: false`, `current_authority_verified: false`,
`current_work_assignment_compared: false`, and `positive_use_approved: false`.
The separate reads cannot provide an atomic cross-store snapshot. A source can
change after the last read. Caller authentication and authorization of the
exact tenant, mission, workspace, and receipt tuple remain external. The
function does not access credentials, invoke an adapter, contact a target,
dispatch a job, publish a finding, or qualify an expert.

Focused tests:

```text
python -m unittest tests.agents.test_offline_action_workspace_link -v
```
