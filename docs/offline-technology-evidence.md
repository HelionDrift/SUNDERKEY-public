# Supplied technology evidence

The `AOE-GA-D01-S10` partial specialist reconciles caller-supplied technology
labels by opaque subject and declared source. It separates contradictory
presence assertions from single-source and multi-source supplied patterns.
It never obtains a response header, manifest, or artifact itself.

The exact native JSON model uses `schema_version: 1`,
`semantics_profile: supplied-technology-evidence-v1`, and 1 to 256
observations. Each observation supplies a unique ID, an opaque digest subject
and source reference, a short technology label, one of `response_header`,
`package_manifest`, `artifact_metadata`, or `operator_assertion`, and an exact
boolean presence assertion. Replay checks, native type restrictions, and
input/output bounds apply.

Distinct source references do not prove source independence. A technology
label is not proof of installed software, version, exposure, or vulnerability.
No network, provider, repository, credential, or target is contacted. The
report grants no action authority, routing status, or qualification. The
[synthetic example](../examples/offline-technology-evidence-component.json)
uses only fictitious labels and opaque references.
