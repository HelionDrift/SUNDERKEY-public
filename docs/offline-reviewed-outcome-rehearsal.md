# Offline reviewed outcome rehearsal

The reviewed outcome rehearsal binds an asserted schedule outcome snapshot to
locally signed work-product review packets. Every `succeeded` task requires
one exact packet with the same task and evidence digests, both independent
review roles locally accepted, and review timestamps no later than the
rehearsal time. Unreviewed, declined, mismatched, or late success claims fail.

The packet deliberately produces no input for live admission. Reviewer public
keys are caller-provided, producer and source custody are not authenticated,
and the schedule, scope, and route are not checked for live currentness. The
result remains `simulation_only: true` with `positive_use_approved: false`.
It is suitable for testing replanning policy and review lineage, not for
authorizing a target action or publishing a finding.
