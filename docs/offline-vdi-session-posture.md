# Supplied VDI Session Posture Review

This R0 partial component belongs to existing specialist `AOE-GC-D16-S07`,
capability `army.gc.d16.s07`, vector `AV-GC-D16-S07-01`, package
`IWP2-AOE-GC-D16-S07`, and wave `IW2-019`. It adds partial A7.4 offline
evidence without completing the specialist or granting live authority.

## Reduced Model And Candidate Rules

`analyze_supplied_vdi_session_posture(model)` accepts one source ID, asserted
inventory completeness, and at most 32 Citrix, VDI or RDS pool rows. Each row
declares remote entry scope, optional session MFA and clipboard-transfer
assertions, data sensitivity, and policy completeness. Complete rows can
produce review signals for declared public entry without MFA or sensitive
data with clipboard transfer. Missing or incomplete policy remains uncertainty.

These are operator-supplied labels, not parsed broker, gateway, directory or
policy-engine settings. They do not prove session access or data exfiltration.

## Replay And Limits

The deterministic content-addressed report requires a separately supplied
original model for replay. The [example](../examples/offline-vdi-session-posture-component.json)
is synthetic. No remote session is started, no data or credential is
transferred, no finding is published, and no operational use is qualified.
