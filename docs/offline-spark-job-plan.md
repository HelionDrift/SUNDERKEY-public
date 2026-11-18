# Supplied Spark job plan

The `AOE-GB-D07-S10` partial specialist compares a caller-supplied job plan
with caller-supplied dataset tenant tags and resource limits. It reports
declared input or output tenant mismatches, per-executor limit differences,
and total requested core and memory arithmetic. When declarations are marked
incomplete, an otherwise aligned job remains unknown. The labels describe
only the supplied model, not an observed Spark or Hadoop cluster.

The exact native JSON model declares `schema_version: 1`,
`semantics_profile: supplied-spark-job-plan-v1`, a completeness boolean, one
bounded policy, up to 128 opaque datasets, and 16 jobs with up to 64 unique
inputs each. Positive integer core, memory, and executor requests are bounded.
The report retains requested totals and exact names of exceeded policy
limits. Input structure and output size are bounded, and the typed report
replays against the original model.

No policy, dataset identity, effective permission, scheduler decision, job
execution, or data processing is verified. A declaration mismatch is not a
finding or proof of unauthorized data access. No Spark, Hadoop, provider,
credential, network, or target is contacted. The projection grants no action
authority or qualification. The
[synthetic example](../examples/offline-spark-job-plan-component.json) uses
only fictitious opaque references.
