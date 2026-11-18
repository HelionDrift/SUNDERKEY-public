# Supplied Native Target Compatibility Review

This R0 partial component belongs to existing specialist `AOE-GC-D17-S07`,
capability `army.gc.d17.s07`, vector `AV-GC-D17-S07-01`, package
`IWP2-AOE-GC-D17-S07`, and wave `IW2-019`. It adds partial A7.4 offline
evidence without completing the specialist or granting live authority.

## Reduced Model And Candidate Rules

`analyze_supplied_native_target_compatibility(model)` accepts one source ID,
asserted inventory completeness, and at most 32 native, Cargo or Go artifact
rows. Each row has opaque package, release and requested-target labels, at most
16 declared supported targets, a target-list completeness assertion, an
optional declared pin, and an artifact digest. The closed model rejects
artifact bytes, commands and credentials.

An absent requested target is a review signal only when the supplied target
list is asserted complete. A digest difference is a separate review signal.
Incomplete target lists, missing pins and incomplete inventory remain explicit
uncertainty, not negative findings.

## Replay And Limits

The deterministic content-addressed report requires a separately supplied
original model for replay. The [example](../examples/offline-native-target-compatibility-component.json)
is synthetic. No package manager, ABI, architecture or toolchain compatibility
check runs. No registry, repository, artifact or target is contacted or executed.
An absent signal does not prove compatibility, integrity or safety.
