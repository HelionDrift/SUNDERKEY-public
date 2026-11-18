# API release-delta review

`compare_api_release_inventories` compares two content-addressed traffic API
inventories around a caller-supplied release identity, artifact digest, and UTC
release time. It is an offline review signal. It does not approve a release,
collect traffic, authorize a target action, or schedule an assessment.

Both snapshots must bind the same tenant, context ID and digest, and signed
scope ID and digest. The baseline snapshot must precede the release boundary;
the current snapshot must follow it. Every baseline endpoint's last observed
event must be before the release, and every current endpoint's first observed
event must be at or after it. Replayed event digests across snapshots are
rejected. The release artifact digest is supplied by the caller and is not
proof that a particular build was deployed.

Both inventories and their endpoint values are captured into owned primitive
views and checked against their supplied digests before comparing lineage.
Release metadata is captured the same way. Caller-defined scalar comparison
or conversion hooks cannot make different underlying tenant or scope values
equal. Valid string and integer enum inputs preserve their underlying canonical
identities; this is local content integrity, not source authentication.

The review records newly observed endpoint shapes, roles, and status codes;
contract mapping or bundle changes; and baseline endpoints not reobserved after the
release. A newly observed role does not prove access, and a newly observed
status does not prove exploitability. A missing post-release observation does
not prove removal. Any such difference produces `review_required`. No
difference produces `inconclusive`, never `passed`, because the repository
cannot establish source completeness, deployed release identity, target
authority, or the quality of live collection.

The result and its source inventory digests are content-addressed. The output
has no authority, qualification, or release-approval effect. A future live
release gate must verify collector identity and coverage, deployed artifact
lineage, policy, current scope and admission, and independent review before
it can claim a passing decision.

This inventory-only contract summarizes roles and statuses independently.
Swapping two roles' response statuses can leave both sets unchanged. The
[matrix-bound release review](api-release-role-response-review.md) addresses
that gap using the exact supplied observations and both role-response matrices.
The delta contract and digest domain are unchanged. Its content address binds
the inventory addresses, which now include their explicit freshness windows.

`verify_api_release_delta_from_sources` replays both source inventories from
their supplied observations and contract bundles, then recomputes the release
comparison. It is a historical derivation check. It does not verify that the
caller supplied every relevant event or that the release artifact was deployed.

Offline validation:

```powershell
$env:PYTHONPATH = 'src'
python -m unittest -q tests.agents.test_api_release_delta_review
```
