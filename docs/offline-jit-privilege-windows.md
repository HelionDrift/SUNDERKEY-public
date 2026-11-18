# Supplied JIT Privilege-Window Projection

This R0 offline component adds partial algorithm coverage for specialist
`AOE-GA-D03-S12`, capability `army.ga.d03.s12`, vector
`AV-GA-D03-S12-01`, work package `IWP2-AOE-GA-D03-S12`, and wave `IW2-013`.
The domain commander is `AOE-GA-D03-CMD`, and independent validation is
assigned to `AOE-HQ-19`. It is not a completed candidate or qualified agent.

The version 1 model compares caller-declared, approved JIT grant windows with
caller-declared revocations and reported outcomes. It uses bounded logical
ticks, not service timestamps. Every source, grant, principal, privilege,
revocation, and observation identifier must be a `synthetic:` label. No
credential, API key, live identity, endpoint, or command is an input.

An active grant is one with declared approval, a half-open window containing
the observation tick, and no listed revocation at or before that tick. A
separate overlapping active grant can still yield a declared allow after
another grant is revoked. Missing policy or ordering completeness remains
unknown. A potentially unlisted revocation prevents an allow projection, and
an incomplete grant inventory prevents a no-grant denial projection.

`analyze_supplied_jit_privilege_windows` emits an unsigned content-addressed
report. `verify_supplied_jit_privilege_windows` and its bounded JSON-byte
variant replay a separately retained original model. The report's embedded
source cannot authenticate itself. The synthetic dispatcher input is
[`offline-jit-privilege-windows-component.json`](../examples/offline-jit-privilege-windows-component.json).

The component models only declared JIT windows. It does not verify PAM
approval, JEA command constraints, actual privilege, revocation enforcement,
or a target response. A candidate mismatch is not a finding or a verified
vulnerability. No network, provider, target, credential, process, filesystem,
or execution action occurs.
