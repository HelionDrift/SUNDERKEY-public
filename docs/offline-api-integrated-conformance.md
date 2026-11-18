# Integrated offline API conformance

One synthetic conformance test now traverses the local boundaries as a single
mission: verified signed scope, API case correlation, Army schedule and roster
rehearsal, independent-review handoff, negative retest with a child world,
schedule replan, locally signed work-product review rehearsal, and a
tenant-bound read-only preview through the SQLite-backed ASGI route.

The test checks that the negative observation creates a conflict without
erasing the prior hypothesis, the new schedule binds to the child snapshot,
review remains pending, and neither the reviewed-outcome rehearsal nor the
preview approves positive use. It uses generated test keys, synthetic evidence,
an injected authorizer, and a temporary local database. No target or provider
is contacted.

This is an integration regression gate, not a production qualification run.
It cannot establish live authorization, reviewer identity custody, or a claim
that a vulnerability was found or fixed.
