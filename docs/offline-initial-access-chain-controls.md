# Supplied Initial-Access Chain Controls

The GA-D04-S02 partial component replays the bounded
[threat-scenario dependency graph](offline-threat-scenario-graph.md)
from an original, synthetic model. It then checks whether a declared
entry stage belongs to an objective's full dependency closure and
projects evidence, action-tier ceiling, authorization, and stop-rule
gaps for every required stage. The checked example is
[`examples/offline-initial-access-chain-component.json`](../examples/offline-initial-access-chain-component.json).

This is a control-coverage rehearsal, not an access route, attack plan,
or permission to act. Every stage and control status is caller-supplied
and unauthenticated. An `asserted` status never becomes verified action
authority. A dependency closure is not proof that an access path is
feasible. The component generates no technique, credential, payload, or
delivery action, and performs no target interaction or qualification.

Independent verification replays the separate original model through
the base scenario analyzer. Missing stage controls are rejected rather
than silently treated as approved. Incomplete inventory and unknown
control states remain explicit uncertainties.
