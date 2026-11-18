# Supplied NTLM Control Pairs

The `AOE-GC-D11-S03` partial specialist, component
`supplied_ntlm_control_pairs`, compares caller-supplied NTLM source and target
pair declarations against a caller-supplied local control policy. For a pair
declared to offer and accept NTLM, the component reports whether required
target signing, Extended Protection for Authentication, or channel-binding
labels were not declared. This is a control-label mismatch, not evidence that
coercion or relay is possible.

The exact native JSON model has `schema_version: 1`, a bounded `source_id`,
`inventory_complete`, `policy`, and one to 64 `pairs`. Source and target
references are opaque SHA-256 references. A complete model with no declared
NTLM exchange returns `no_applicable_supplied_pairs`, not a positive match.
Incomplete inventory yields `unknown`, no candidates, and one unknown row per
pair. Replay verification recomputes the report from the separately supplied
original model.

The component does not induce authentication, relay traffic, use a credential,
contact a service or target, prove exploitability, publish a finding, or grant
qualification. The [synthetic example](../examples/offline-ntlm-control-pairs-component.json)
uses fictitious digest references only.
