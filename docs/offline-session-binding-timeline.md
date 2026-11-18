# Supplied session binding and invalidation timeline projection

This R0 partial component serves specialist `AOE-GA-D03-S16`, capability
`army.ga.d03.s16`, vector `AV-GA-D03-S16-01`, package
`IWP2-AOE-GA-D03-S16`, and scheduled wave `IW2-017`. Its component ID is
`identity_supplied_session_binding_timeline`. It contributes partial offline
evidence only. It does not qualify the specialist, validate a session, or
authorize live use.

`analyze_session_binding_timeline(*, source_content: bytes, source_id: str)`
accepts bounded UTF-8 JSON with `schema_version` (`v1`), exact event, policy,
device-binding and concurrency completeness flags, a three-boolean policy, and ordered `issue`, `rotate`,
`revoke`, and `observe` events. Session and device IDs must match the bounded
`synthetic:` label grammar. They must not be real tokens, cookies, secrets,
or credential material. The prefix is a format guard, not proof of source
sanitization. Events have unique IDs, closed fields, and bounded arrays.
Complete sequences reject unsupported issuance, rotation, and revocation
lineages. A partial or concurrency-ambiguous sequence is not interpreted
for a positive policy comparison.

Only negative invariants are projected: a revoked session when the supplied
policy requires invalidation and the observation explicitly asserts that
revocation was effective beforehand; a rotated-old session when immediate
invalidation is explicitly required; or a different device when binding is
explicitly required. A revoke event's list position alone does not establish
effective revocation. If the revoke policy is false or effectiveness is false
or unknown, the revoked-session branch is `unknown`, even when a supplied
outcome says `allowed`. A supplied `allowed` outcome
against one of those negative invariants yields
`candidate_declared_negative_policy_conflict`; a supplied `denied` outcome
is `declared_deny_consistent`. All other observations are `unknown`, rather
than evidence of authorization. Incomplete events, policy, device bindings,
concurrency ordering, individual observation, or outcome also yield `unknown`. The
event order is caller-supplied and cannot establish a real server ordering.
No token is replayed, no device is inspected, and no actual session behavior
or vulnerability is claimed.

The report binds exact source bytes by SHA-256 and includes per-observation
projections, counts, fixed no-effect fields, and explicit non-live flags.
`SessionBindingTimelineReport.from_json` checks local report shape and
address only. `verify_session_binding_timeline` replays separately supplied
original bytes and compares the whole report. The exact native adapter is
`analyze_supplied_session_binding_timeline({"source_id": ..., "source":
...})`. The synthetic common-envelope request is
`examples/offline-session-binding-timeline-component.json` and uses empty
network, filesystem, process, and credential resources. No target, network,
provider, credential, process, or live exploit occurs.
