# Supplied Resource Expansion Budget

The `AOE-GE-D23-S11` partial specialist computes a finite arithmetic work
projection from caller-supplied input units, fanout, and depth. It compares
that projection with a caller-supplied capacity and rejection policy. The
calculation has fixed small bounds and saturates at 1,000,000,001 units so
it can decide whether a declared capacity of at most 1,000,000,000 units is
exceeded without expanding a workload.

A complete declared policy and capture with an over-capacity projection and
a declared accepted outcome yield only a
`candidate_declared_resource_budget_conflict`. Missing declaration or
capture, or an unknown outcome, withholds that conclusion. The expansion
factors, policy, capacity, and outcome are unverified caller assertions.
Projected work is not measured target resource use, and a declared conflict
does not prove resource exhaustion or availability impact.

The model permits at most 128 operations within a 64 KiB native document
bound. Its report embeds the original model for separate-source replay.
No workload, file, network, process, credential, target, publication,
execution, or qualification effect occurs. The
[synthetic example](../examples/offline-resource-expansion-budget-component.json)
contains only arithmetic declarations.
