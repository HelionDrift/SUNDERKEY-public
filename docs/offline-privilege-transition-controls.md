# Supplied Privilege-Transition Control Projection

The GA-D04-S07 partial component replays an original, synthetic
[threat-scenario dependency graph](offline-threat-scenario-graph.md),
then compares caller-declared privilege tiers across direct stage
dependencies. Each tier increase is checked for a supplied review-gate
status. The checked example is
[`examples/offline-privilege-transition-controls-component.json`](../examples/offline-privilege-transition-controls-component.json).

Missing reviews are gaps only in the supplied model. Unknown reviews,
incomplete stage inventory, nonsupplied stage evidence, and high-tier
root stages remain explicit uncertainties. A review marked `asserted`
is not verified authority. The tiers do not represent measured
privileges, and a stage transition is not a demonstrated escalation.
No escalation method, payload, credential, target interaction,
candidate, or qualification is produced.

Independent verification replays the separate original model. Stage
privilege records must cover the exact graph inventory; duplicates,
missing stages, and nonsynthetic input are rejected.
