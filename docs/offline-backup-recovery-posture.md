# Supplied Backup And Recovery Posture Review

This R0 partial component belongs to existing specialist `AOE-GC-D16-S08`,
capability `army.gc.d16.s08`, vector `AV-GC-D16-S08-01`, package
`IWP2-AOE-GC-D16-S08`, and wave `IW2-020`. It adds partial A7.4 offline
evidence without completing the specialist or granting live authority.

## Reduced Model And Candidate Rules

`analyze_supplied_backup_recovery_posture(model)` accepts one source ID,
asserted inventory completeness and at most 32 asset rows. Each row declares
whether backup is required, whether it is enabled or unknown, maximum recovery
point and restore-test ages, and optional latest observed ages. The ages are
bounded integer seconds supplied by the caller, not clock-verified timestamps.

For required assets, asserted disabled backup or an age beyond a supplied
limit creates a review signal. Missing enablement or age remains uncertainty.
Assets declared not to require backup do not produce policy-difference signals.
The result does not determine whether a recovery point exists or a restore
would succeed.

## Replay And Limits

The deterministic content-addressed report requires a separately supplied
original model for replay. The [example](../examples/offline-backup-recovery-posture-component.json)
is synthetic. No backup catalog, clock, storage system, asset or restore
operation is accessed. The component does not authenticate a source, publish
a finding, prove failed recovery or qualify operational use.
