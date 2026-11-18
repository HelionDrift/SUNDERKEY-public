# Supplied RMM Control Posture Review

This R0 partial component belongs to existing specialist `AOE-GC-D16-S11`,
capability `army.gc.d16.s11`, vector `AV-GC-D16-S11-01`, package
`IWP2-AOE-GC-D16-S11`, and wave `IW2-023`. It adds partial A7.4 offline
evidence without completing the specialist or granting live authority.

## Reduced Model And Candidate Rules

`analyze_supplied_rmm_control_posture(model)` accepts one source ID, asserted
inventory completeness, and at most 32 fleet rows. Each row declares optional
remote-control enablement, operator scope, optional approval requirement,
agent-inventory completeness, and policy completeness. A complete, enabled
fleet can produce review signals for broad control scope or control without a
declared approval gate. Missing states and incomplete inventory remain
uncertainty. A declared disabled fleet does not produce control-scope signals.

The labels are not parsed product policy or verified operator authority.
The component cannot prove that an agent or endpoint is controllable.

## Replay And Limits

The deterministic content-addressed report requires a separately supplied
original model for replay. The [example](../examples/offline-rmm-control-posture-component.json)
is synthetic. No command, agent, tenant, managed endpoint or credential is
used. No finding is published and no operational use is qualified.
