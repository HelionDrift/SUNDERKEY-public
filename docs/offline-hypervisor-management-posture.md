# Supplied Hypervisor Management Posture Review

This R0 partial component belongs to existing specialist `AOE-GC-D16-S06`,
capability `army.gc.d16.s06`, vector `AV-GC-D16-S06-01`, package
`IWP2-AOE-GC-D16-S06`, and wave `IW2-018`. It adds partial A7.4 offline
evidence without completing the specialist or granting live authority.

## Reduced Model And Candidate Rules

`analyze_supplied_hypervisor_management_posture(model)` accepts one source ID,
asserted inventory completeness, and at most 32 manager rows. Each row has a
platform family, management reachability, optional admin MFA assertion,
snapshot-mutation role scope, and scope-completeness assertion. Complete rows
can produce review signals for declared public management reachability, public
administration without MFA, or broad snapshot-mutation scope. Missing or
incomplete scope remains uncertainty.

These are operator-supplied labels, not a parsed API, firewall, directory or
privilege policy. The component cannot establish effective access or VM state.

## Replay And Limits

The deterministic content-addressed report requires a separately supplied
original model for replay. The [example](../examples/offline-hypervisor-management-posture-component.json)
is synthetic. No hypervisor, manager, VM or target is contacted or changed.
No finding is published and no operational use is qualified.
