# Supplied Managed Package Feed Review

This R0 partial component belongs to existing specialist `AOE-GC-D17-S06`,
capability `army.gc.d17.s06`, vector `AV-GC-D17-S06-01`, package
`IWP2-AOE-GC-D17-S06`, and wave `IW2-018`. It adds partial A7.4 offline
evidence without completing the specialist or granting live authority.

## Reduced Model And Candidate Rules

`analyze_supplied_managed_package_feed(model)` accepts one source ID, asserted
inventory completeness, and at most 32 Maven or NuGet rows. Each row has opaque
coordinate, release, intended-feed and selected-feed labels, an optional
declared artifact pin, a selected artifact digest, and an asserted verification
state. The closed model rejects package bytes, credentials and commands.

A supplied feed difference, digest difference or asserted verification failure
creates a review signal. A missing pin, unknown verification state or incomplete
inventory remains explicit uncertainty. These are comparisons of operator-supplied
labels, not findings or proof of a dependency-confusion path.

## Replay And Limits

The deterministic content-addressed report requires a separately supplied
original model for replay. The [example](../examples/offline-managed-package-feed-component.json)
is synthetic. No Maven or NuGet parser, version resolver, feed, signature
service, repository, artifact or target is used. The component does not install
packages, authenticate a source, publish a finding or qualify operational use.
