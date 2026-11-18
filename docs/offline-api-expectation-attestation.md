# Local API access expectation attestation

`sunderkey.offline_api_expectation_attestation` is an opt-in local signature
rehearsal for a separate expected-access assertion set. It reproduces the
content-addressed assertion before signing its exact digest, mission, target,
scope, object, action, asserted policy-owner reference, and key reference.
The verifier checks the Ed25519 signature against a caller-pinned public key.
It requires exact JSON types for signed context fields, including false safety
flags, so an integer zero cannot replay as a signed boolean false.
The signed-case binding additionally replays the synthetic API case and checks
its evidence labels against that exact assertion set.
The signed-retest binding applies the same signature and assertion set to both
replayed cases and their comparison, without turning a synthetic observation
change into proof of a fix.

Call `sign_offline_api_access_expectations` with a caller-held private key,
then `bind_offline_api_case_to_signed_access_expectations` with the matching
`OfflineAccessPolicyKeyBinding`. Use the two verifiers to reproduce the
signature and signed-case packet.
For a prior case and retest, use
`bind_offline_api_retest_to_signed_access_expectations` and its matching
verifier with the same assertion set and signer binding.

At consumption, the exact `OfflineAccessPolicyKeyBinding` family is required.
Its current native owner and key identifiers and Ed25519 public key are
captured and revalidated before use. Signed context, digest and signature
strings and all mapping keys must be native JSON strings; the effects object
must contain native keys and string values. Caller string hooks and aliased
fields are rejected before lookup or comparison. The verified result is a
detached canonical JSON document, not a shallow alias of caller effects.
Native-key read-only document views remain supported, and ordinary JSON
attestation and signed-case identities are unchanged.
Expectation context keys, identity and digest strings, and principal identity
keys and strings are also checked before the upstream assertion replay.

This does not authenticate a real policy owner or customer authorization.
Local signing may occur after observation and therefore does not prove a
pre-observation commitment. The case evidence and policy correctness are not
independently authenticated. The output cannot approve positive use, publish
a finding, authorize execution, or qualify a system.
These checks do not establish general ownership of arbitrary caller mappings
or protection against concurrent caller mutation.
