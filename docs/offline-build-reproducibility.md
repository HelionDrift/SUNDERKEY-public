# Supplied Build Reproducibility Review

This R0 partial component belongs to existing specialist `AOE-GC-D17-S09`,
capability `army.gc.d17.s09`, vector `AV-GC-D17-S09-01`, package
`IWP2-AOE-GC-D17-S09`, and wave `IW2-021`. It adds partial A7.4 offline
evidence. It neither completes the specialist nor grants qualification or live
authority.

## Reduced Model And Candidate Rules

`analyze_supplied_build_reproducibility(model)` accepts one source ID, an
asserted inventory-completeness flag, and at most 32 reduced build-run rows.
Each row has an opaque run ID, SHA-256 labels for source, build definition,
toolchain, declared inputs and artifact, plus asserted input completeness,
sandboxing and network-access flags. Command lines, environment variables,
source files, logs, credentials and artifact bytes are not accepted.

The component reports a review signal when a supplied run is unsandboxed or
network access is allowed. It reports divergent-artifact signals for runs that
have identical four-part declared input labels, all assert complete inputs,
but have different artifact labels. Incomplete declared inputs or an incomplete
inventory remain explicit uncertainty. Matching labels are only a negative
result for this narrow comparison, not build-integrity proof.

## Replay And Limits

The report is deterministic, content-addressed and bound to the separately
supplied original model through `verify_supplied_build_reproducibility`. The
synthetic [example](../examples/offline-build-reproducibility-component.json)
uses only inert labels. All metadata is operator-supplied and unauthenticated.
The component does not execute a compiler, build, process or container, access
a repository or registry, read artifact bytes, contact a target, publish a
finding or prove compromise. Even a fully declared same-input difference may
reflect benign nondeterminism.
