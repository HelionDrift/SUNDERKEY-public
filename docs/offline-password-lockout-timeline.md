# Supplied Password-Lockout Timeline Projection

This R0 offline component adds partial algorithm coverage for specialist
`AOE-GA-D03-S01`, capability `army.ga.d03.s01`, vector
`AV-GA-D03-S01-01`, work package `IWP2-AOE-GA-D03-S01`, and wave `IW2-002`.
The domain commander is `AOE-GA-D03-CMD`, and independent validation is
assigned to `AOE-HQ-19`. It is not a completed candidate or qualified agent.

The version 1 model accepts synthetic account and event labels, a declared
maximum consecutive failure count, a logical lockout duration, strictly
ordered logical ticks, completeness flags, and reported outcomes. It accepts
no password, hash, credential, endpoint, or target. The bounded model
projects only whether a reported success falls inside a lockout implied by
earlier declared failures. It does not infer password validity or a successful
authentication outside a lockout.

Incomplete policy, event coverage, or ordering makes every projection
unknown. A failure reported inside a declared lockout is only consistent
with the negative invariant. A reported success inside the declared lockout
is a candidate declared conflict, not evidence of a bypass. The report does
not recommend timing, attempt rates, or attack pacing.
An unknown outcome makes later projections for that account unknown.

`analyze_supplied_password_lockout` emits an unsigned content-addressed
report. Verification replays a separately retained original model through
`verify_supplied_password_lockout` or its bounded JSON-byte variant. The
report's embedded source cannot authenticate itself. A synthetic dispatcher
input is in
[`offline-password-lockout-timeline-component.json`](../examples/offline-password-lockout-timeline-component.json).

No authentication attempt, target interaction, credential use, network,
provider, process, filesystem, finding publication, or qualification occurs.
A candidate mismatch is not a verified vulnerability.
