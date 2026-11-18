# Supplied Biometric Assurance Projection

This R0 offline component adds partial algorithm coverage for specialist
`AOE-GA-D03-S17`, capability `army.ga.d03.s17`, vector
`AV-GA-D03-S17-01`, work package `IWP2-AOE-GA-D03-S17`, and wave `IW2-001`.
The domain commander is `AOE-GA-D03-CMD`, and independent validation is
assigned to `AOE-HQ-19`. It is not a completed candidate or qualified agent.

The version 1 model accepts only synthetic source, record, and nonce labels.
A caller declares whether liveness, device binding, and unique nonce labels
are required, whether policy, record coverage, and ordering are complete, and each
reported acceptance or rejection. For an accepted record, a declared missing
required signal or reused nonce label becomes a candidate declared conflict.
It does not establish a real sensor reading, cryptographic freshness, or a
presentation attack. Unknown required signals suppress a candidate.

`analyze_supplied_biometric_assurance` emits an unsigned content-addressed
report. Verification replays a separately retained original model through
`verify_supplied_biometric_assurance` or its bounded JSON-byte variant. The
embedded model cannot authenticate itself. A synthetic dispatcher input is
in [the component example](../examples/offline-biometric-assurance-component.json).

The component does not accept or process biometric images, samples, templates,
sensor data, real nonce values, credentials, endpoints, or target responses.
No enrollment, authentication attempt, device interaction, finding
publication, positive use, or qualification occurs.
