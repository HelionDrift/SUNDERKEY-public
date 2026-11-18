# Supplied API rate-limit projection

This R0 partial component belongs to `AOE-GB-D06-S13`, capability
`army.gb.d06.s13`, vector `AV-GB-D06-S13-01`, and wave `IW2-004`.
It compares caller-supplied admission records with a caller-declared fixed
window limit. It never sends requests, measures a provider, or establishes
that a deployed API permits excess traffic.

The bounded version `v1` source declares a window duration and origin,
per-route limits, a traffic-completeness flag, and ordered event IDs with
timestamps, subjects, routes, and `admitted` or `rate_limited` outcomes.
The projection groups admitted outcomes by subject, route, and fixed window.
Only a complete supplied traffic record can produce
`candidate_admitted_over_limit`; incomplete records remain
`unknown_incomplete_traffic`. A zero candidate count does not prove a live
rate-limit control. The report retains source digest, window IDs and counts,
not network observations.

`analyze_supplied_api_rate_limit(model)` is the catalog adapter. Its exact
native model has `source_id` and `source`; the latter is canonicalized before
the byte-level analyzer runs. `verify_api_rate_limit` requires the separately
supplied source bytes. The common component verifier replays the original
request and current catalog. The checked example is
`examples/offline-api-rate-limit-component.json`. No execution, target,
provider, qualification, or routing authority is created.
