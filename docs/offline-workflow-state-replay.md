# Supplied workflow state replay

The `AOE-GB-D09-S01` partial specialist replays a caller-supplied finite
workflow model and ordered event list. It distinguishes rejected events,
unknown accepted transitions, accepted from-state mismatches, accepted events
from a declared terminal state, guards not declared satisfied, and declared
state mismatches. Accepted events advance only this local projection. The
original model and each event position remain in the replay-checked report.

The exact native JSON model declares `schema_version: 1`,
`semantics_profile: supplied-workflow-state-replay-v1`, an opaque digest-shaped
`workflow_ref`, one to 128 unique states, terminal states, initial state, one
to 512 named transitions, and one to 512 events. Transitions name a from-state,
to-state, and opaque guard label. Events contain a transition label, declared
before and after states, a guard outcome, and an accepted or rejected result.
All counts, strings, structure, and report bytes are bounded. The typed report
can be independently replayed from the current supplied model.

State definitions, guard truth, event order, outcomes, and labels are supplied
assertions. A flagged transition is a review observation, not proof that a
deployed service has a defect. This component does not authenticate a source,
exercise a workflow, contact a target, change business state, appoint a
reviewer, approve positive use, or qualify a candidate. The
[synthetic example](../examples/offline-workflow-state-component.json) contains
only fictitious states and events.
