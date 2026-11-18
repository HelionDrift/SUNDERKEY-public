# Supplied SAN And NAS Access Posture Review

This R0 partial component belongs to existing specialist `AOE-GC-D16-S09`,
capability `army.gc.d16.s09`, vector `AV-GC-D16-S09-01`, package
`IWP2-AOE-GC-D16-S09`, and wave `IW2-021`. It adds partial A7.4 offline
evidence without completing the specialist or granting live authority.

## Reduced Model And Candidate Rules

`analyze_supplied_storage_access_posture(model)` accepts one source ID,
asserted inventory completeness and at most 32 resource rows. Each row has
supplied protocol, data sensitivity, exposure scope, write scope and a scope
completeness assertion. A complete row that declares sensitive public
exposure or public write scope produces a review signal. Unknown or incomplete
scope remains uncertainty rather than a negative finding.

These are opaque operator labels, not parsed ACL, export, initiator, zone or
authentication rules. The component does not establish public reachability,
effective authorization or data readability.

## Replay And Limits

The deterministic content-addressed report requires a separately supplied
original model for replay. The [example](../examples/offline-storage-access-posture-component.json)
is synthetic. No storage system or target is contacted. No data or credential
is read or written, no finding is published and no operational use is qualified.
