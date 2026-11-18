# Supplied deception cues

The `AOE-GA-D01-S12` partial specialist reconciles caller-supplied cues for
review. It groups explicit presence assertions by opaque subject and cue label,
reports contradictory assertions, and identifies multi-source supplied
patterns. It does not classify a live service as a honeypot.

The exact native JSON model uses `schema_version: 1`,
`semantics_profile: supplied-deception-cues-v1`, and 1 to 256 observations.
Kinds are restricted to `synthetic_marker`, `service_identity_conflict`,
`route_identity_conflict`, and `operator_assertion`. Each row has an opaque
subject and source digest, a short label, a unique ID, and an exact boolean
presence assertion. Replay checks, native type restrictions, and bounds apply.

All cues and source claims are unverified caller statements. A multi-source
pattern is a review candidate, not proof of deception. No live probe, target,
network, credential, provider, or service is touched. The report grants no
action authority, routing status, or qualification. The
[synthetic example](../examples/offline-deception-evidence-component.json)
uses only fictitious labels and opaque references.
