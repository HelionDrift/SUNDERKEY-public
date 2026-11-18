# Matrix-bound API release role-response review

`compare_api_release_role_responses` composes the unchanged inventory-only
release delta with a role-response matrix from each complete supplied observation
window. It preserves the association `(origin, method, path_shape, role_ref,
status_code)` rather than comparing role and status sets independently. For
example, swapping the observed statuses of two roles is a review signal even
when both endpoint marginals stay unchanged.

## Source and content integrity

The builder requires typed baseline and current inventories, their exact
observation tuples, and an explicit release identity, artifact digest and UTC
boundary. Tenant, context and scope IDs and revisions must agree. The existing
release checks enforce snapshot order, separate before/after event windows and
no repeated observation digest across that boundary. Matrix construction also
requires exact coverage of each inventory and its endpoint aggregation.

Both traffic consumers verify observation digests against owned reconstructions
before use. A frozen object's changed fields cannot silently retain the old
source digest, and a custom body override cannot change what gets verified.
These checks do not authenticate collector, role, scope, or release assertions.

Both source inventories are captured into owned primitive views before the
delta, matrices and final bindings are derived. String and integer enums in
valid source observations retain their original canonical identities while
becoming plain output values. Caller-defined equality, ordering, conversion or
tuple iteration cannot change those comparisons. The portable review parser
continues to require exact primitive wire types and does not accept enum objects.

The review binds both snapshot times, both inventory and matrix digests, the
unchanged inventory delta's digest, gate and reasons, newly observed and
not-reobserved associations, their reobserved intersection count, and the
derived overall gate and reasons. Its digest domain is
`sunderkey.api-release-role-response-review.v1`. The output schema is
`registry/schemas/api-release-role-response-review-v1.schema.json`.

## Gate semantics

Any newly observed association, or a legacy inventory delta requiring review,
produces `review_required`. Substantive legacy reasons are retained. Association
changes replace the legacy no-difference placeholder with their specific reasons.
An association absent from the current window is only `not_reobserved`; it does
not prove removal, revocation, denial, or a fixed vulnerability. Missing-only
associations are `inconclusive` when the legacy delta is also inconclusive.
A missing endpoint still retains the legacy review-required coverage gap.
Unchanged associations remain inconclusive, never passed or release-approved.

There can be up to 10,000 distinct associations on each side. Both difference
lists may independently reach that ceiling. Counts, disjointness, sorted unique
associations, closed HTTP methods, redacted paths and exact primitive types are
validated without coercion or silently discarding malformed entries.

`ApiReleaseRoleResponseReview.from_dict` checks the closed portable wire shape
and its internal identity. `verify_api_release_role_response_review` additionally
rebuilds from the complete original sources and compares the entire result.
An internally consistent supplied hash is not source authentication or approval
for current use. The fixed-depth parser preserves the existing 10,000-observation
windows instead of imposing smaller trace-review byte or node limits. The
existing canonical-origin contract has no string-length ceiling, so this module
does not claim a global serialized-byte limit.

## Planning integration and exclusions

`event_from_evidence` accepts the typed review with an explicit observation time
at or after its current snapshot. It retains the `api_release_delta` event kind
and binds the review's digest. Only `review_required` sets its change signal.
The existing candidate planner still applies stop, freshness, duplicate,
cooldown and budget controls, and exact source-event replay. No scheduling,
notification, delivery, storage, transport or target operation is added.

Effects are fixed to `none` and exports are detached dictionaries. This is
offline review and proposal evidence, not an authorization verdict, production
collection, exploit validation, deployed release proof, finding publication,
independent human review, qualification or a claim of vendor parity.

```powershell
$env:PYTHONPATH = 'src'
python -m unittest tests.agents.test_api_traffic_observation_integrity tests.agents.test_api_release_role_response_review tests.agents.test_api_release_role_response_events -q
```
