# Supplied service-worker scope and page-control projection

This R0 partial component serves existing specialist `AOE-GB-D05-S16`,
capability `army.gb.d05.s16`, vector `AV-GB-D05-S16-01`, package
`IWP2-AOE-GB-D05-S16`, and wave `IW2-001`. It adds partial A7.4 offline
evidence only. It does not complete the specialist, candidate, qualification,
independent-validation, or live-use gate.

`analyze_service_worker_scope(*, source_content: bytes, source_id: str)`
accepts one bounded UTF-8 JSON source with exactly `schema_version` (`v1`),
`facts_complete`, `registration_set_complete`, `registrations`, and
`observations`. A registration declares an ID, origin ID, script path, scope
path, and state (`active`, `inactive`, or `unknown`). An observation declares
an ID, page origin ID and path, supplied control outcome (`controlled`,
`uncontrolled`, or `unknown`), and controller registration ID only when the
outcome is `controlled`. Each observation also asserts whether
`registration_snapshot_applies`: the page controller state derives from the
supplied registration snapshot, with no prior controller persisting across a
registration change. Origin IDs and paths are inert labels. Paths must be
bounded exact ASCII paths without dot segments, percent encoding, query,
fragment, or authority. Duplicate JSON keys, unknown fields, duplicate
registration IDs or exact origin/scope pairs, and over-bound data fail closed.

Under complete supplied premises, registrations match a page only when its
declared origin ID is equal and the page path begins with the declared scope
path. The most specific active matching scope determines the expected
controller. A matching unknown-state scope at least as specific as the best
active scope makes the expected controller `unknown`; an unknown less-specific
scope does not erase a more-specific active result. No active or unknown
match projects `uncontrolled` only when the observation asserts snapshot
applicability. Incomplete facts, registration inventory, or snapshot
applicability projects `unknown`, not a negative result. A supplied observation
opposite the resolved projection is `candidate_control_contradiction`, not a
verified browser behavior or vulnerability. The projection does not decide
whether a script can register a scope, including any Service-Worker-Allowed
header effect, nor does it model installation, lifecycle, extension privileges
or actual URL canonicalization. The snapshot applicability flag is a supplied
premise, not proof of browser lifecycle state.

The report includes the exact source digest and byte count, sorted
per-observation projections, matching registration IDs, summary counts,
limitations, and no-effect flags. `ServiceWorkerScopeReport.from_json`
validates only local report structure and address. It does not prove
derivation. `verify_service_worker_scope(report, *, source_content,
source_id)` replays exact original source bytes and compares the entire
report before it can be trusted as a source-bound projection.

`analyze_supplied_service_worker_scope(model)` is the catalog adapter. Its
exact native model contains `source_id` and `source`, where `source` matches
`component_fixture()`. The checked synthetic common-envelope example is
`examples/offline-service-worker-scope-component.json`. Its R0 dry run has
empty network, filesystem, process, and credential resources. No browser,
service worker, extension, network, filesystem, process, credential,
execution, target, authority, routing, qualification or deployment effect
is granted.
