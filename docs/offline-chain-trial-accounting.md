# Supplied Chain-Trial Accounting

The GE-D21-S18 component counts outcomes in a bounded, caller-supplied
sequential stage and trial table. It requires each attempted stage to have a
Boolean outcome. After the first failed stage, all later stages must be
explicitly unattempted. The report separates stage attempts, successes,
first failures, full-chain successes, and counts by supplied environment.

No trial is executed or authenticated. Stage order, outcomes, and environment
labels are supplied assertions. Counts are not a statistical reliability
estimate, proof of mitigation bypass, or proof of independent repetitions.
Incomplete trial inventories remain unknown. The component creates no
finding, candidate, qualification, or action authority.

The checked synthetic example is
[`examples/offline-chain-trial-component.json`](../examples/offline-chain-trial-component.json).
Verification requires replay against the original supplied model.
