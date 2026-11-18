# Offline API assessment correlation

`sunderkey.offline_api_assessment` composes the Phase 157 native synthetic API
reference adapter with the Phase 160 authorization-differential validator. It
uses the same caller-supplied typed response records for both paths. The adapter
receives only redacted status and identity metadata; response bytes remain in
memory for the validator and do not appear in the correlation result.

The adapter can flag a differential from one unauthorized success. The
validator requires an authorized control, a distinct unauthorized principal,
the same object and action, and matching response representations before it
reports its `verified` state. The combined result is only a
`corroborated_synthetic_signal`. It is not a published finding or an independent
human review. An unauthorized success without matching representation remains
`review_required`; a denied unauthorized request with a successful authorized
control is a `negative_synthetic_result`.

Every response must carry an explicit principal and Boolean access expectation.
For one object and action, a principal cannot be both the authorized control and
the unauthorized subject. Conflicting access expectations, missing principal
identities, and incomplete access labels cause the validator to abstain. A third
principal elsewhere in the response set cannot repair a same-principal match.
Repeated observations with different status codes are allowed when the access
expectation is consistent. Ambiguous cases remain `review_required` and cannot
produce a hypothesis edge through the API world projection.

The entry point requires the exact native API profile, a synthetic R0 dry-run
invocation, no credential references, a deny-all resource policy, and one to 64
typed response records. Every adapter exchange must match the evidence ID,
principal, object, expected access, and status code exactly. The output binds
the manifest, adapter result, validator result, and sorted evidence digests.
Its strict wire shape is
`registry/schemas/offline-api-assessment-result-v1.schema.json`.
`verify_offline_api_case` re-runs both components and compares every result
field. Neither function reads a file, opens a socket, invokes a tool, acquires
credentials, or changes persistent state.

Source replay uses the current exact authorization validator, version `1.0.1`,
and its current default-registry identity. An artifact produced by the previous
rule is not accepted merely because its original content address is intact or
its outcome label still agrees. Preserve that artifact unchanged and build a
new result from the original sources. Case, retest, batch, and downstream source
verifiers do not offer a historical-rule fallback. Archived planning containers
can instead use the separately non-authorizing
[integrity inspector](offline-api-planning-bundle.md); archive integrity does
not approve the old result for current planning or execution.

`compare_offline_api_retest` reproduces both supplied cases before comparing
them. It requires distinct case, invocation, and evidence identities and the
same mission, target, scope, adapter, object, and action. A change from a
corroborated synthetic signal to a negative synthetic result is labeled only
`prior_signal_not_observed_in_second_synthetic_case`. The caller's order is
not authenticated chronology, and the comparison is not a verified fix. The
strict comparison shape is
`registry/schemas/offline-api-retest-result-v1.schema.json`.
`verify_offline_api_retest` reproduces both source cases and the comparison
before accepting any supplied result. Receipt-sourced retests use the same
cross-case receipt, scope, target, and session consistency checks as batches;
renaming an evidence record cannot make one HTTP receipt a second observation.

This is the first executable offline composition seam, not a complete product
assessment loop. Source provenance, target authorization, containment,
independent review, findings, reports, retest, and production deployment remain
separate gates. The result has no authorization, target-execution, network,
qualification, deployment, or finding-publication effect.

Focused verification:

```powershell
$env:PYTHONPATH = "src"
python -m unittest -q tests.agents.test_offline_api_assessment
```

## Local synthetic command

The checkout also includes a bounded command and a synthetic example. Run it
from the repository root with `PYTHONPATH=src`. It reads only the local JSON
case, validates the checked-in adapter catalog against its source, and prints
an effect-free result. The case body is not printed in the result.

```powershell
$env:PYTHONPATH = "src"
python -m scripts.run_offline_api_assessment run --input examples/offline-api-assessment/corroborated-synthetic-case.json > offline-api-result.json
python -m scripts.run_offline_api_assessment verify --input examples/offline-api-assessment/corroborated-synthetic-case.json --result offline-api-result.json
```

The JSON input is capped at 256 KiB, rejects duplicate keys and unknown
fields, and accepts only JSON object or array response bodies. The command
forces synthetic R0 dry-run settings and accepts no URL, credential, network
transport, tool, or live-execution option. It cannot establish whether a
caller-supplied case actually came from a synthetic source. Do not use real
target responses or secrets as fixtures, and do not treat a local result as
target authorization, a verified finding, or production assessment evidence.

For a synthetic observation comparison, first run the second case, then
compare the two reproduced results. Keep the generated JSON files outside
the tracked source tree when using non-example data.

```powershell
python -m scripts.run_offline_api_assessment run --input examples/offline-api-assessment/denied-synthetic-retest-case.json > offline-api-second.json
python -m scripts.run_offline_api_assessment retest --prior-input examples/offline-api-assessment/corroborated-synthetic-case.json --prior-result offline-api-result.json --second-input examples/offline-api-assessment/denied-synthetic-retest-case.json --second-result offline-api-second.json > offline-api-comparison.json
python -m scripts.run_offline_api_assessment retest-verify --prior-input examples/offline-api-assessment/corroborated-synthetic-case.json --prior-result offline-api-result.json --second-input examples/offline-api-assessment/denied-synthetic-retest-case.json --second-result offline-api-second.json --comparison offline-api-comparison.json
```

The comparison validates case bindings and evidence digests. It does not
authenticate time order or conclude that a vulnerability was fixed.

For a bounded assessment rollup, pass one to 64 case and result pairs. Each
result is reproduced before counting it. The rollup requires a single mission,
scope, and checked-in adapter and rejects duplicate case IDs, invocation IDs,
or evidence. For receipt-sourced cases it also rejects a receipt reused under
a different evidence identity, mixed sourced and unsourced cases, changes to
the asserted scope digest or a target's digest, and a single session relabeled
as different principals across cases. These checks do not authenticate the
receipt producer or the caller's principal assertion. The rollup lists cases
needing review without assigning a reviewer or publishing a finding. A
mixed-observation binding means only that different
synthetic outcomes were supplied for the same target, object, and action.

```powershell
python -m scripts.run_offline_api_assessment batch --case examples/offline-api-assessment/corroborated-synthetic-case.json offline-api-result.json --case examples/offline-api-assessment/denied-synthetic-retest-case.json offline-api-second.json > offline-api-batch.json
python -m scripts.run_offline_api_assessment batch-verify --case examples/offline-api-assessment/corroborated-synthetic-case.json offline-api-result.json --case examples/offline-api-assessment/denied-synthetic-retest-case.json offline-api-second.json --batch-result offline-api-batch.json
```

The strict rollup shape is
`registry/schemas/offline-api-assessment-batch-v1.schema.json`. It contains
only case IDs, target IDs, result and binding hashes, dispositions, counts,
and explicit no-effect fields. It is not an assessment report or a live
coverage claim.

## Receipt-bound response evidence

`sunderkey.offline_api_receipt_evidence.bind_http_response_evidence` converts
caller-supplied response bytes into typed API evidence only after the existing
authorized HTTP receipt verifier succeeds. The supplied bytes must match the
receipt's response digest and size. The receipt must describe a completed
exchange, and its scope ID and digest, target ID and digest, and session ID
must match explicit caller expectations. The resulting evidence includes the
receipt digest, source session, scope, and target bindings in its content
address. The API assessment path checks those source IDs against its invocation
and rejects reused receipt digests, mixed source contexts, sourced and
unsourced record mixtures, and one session labeled as multiple principals.

The converter does not read a file or call a transport. A content-addressed
receipt does not authenticate its origin, prove that its backend was a real
target, or establish that a caller's principal label and expected-access
assertion are true. An injected test backend can produce a valid receipt.
Use this bridge for offline integration and review, not to promote a case to
live finding or execution authority. Response bytes remain in memory and are
not included in the assessment result.

## Human-review proposal handoff

`sunderkey.offline_api_review_handoff` reproduces every API case and its batch
before creating `HumanReviewCase` records for the batch's nonnegative review
candidates. It then uses the existing human-review router to propose technical,
independent Control, and independent Assurance slots. With no eligible roster,
the slots remain unfilled. Negative-only batches create no handoff. Each case
references its reproduced result digest, and the handoff binds the exact batch
and routing-plan digests. The input tenant, originating principal and team,
scope binding digest, times, and roster are caller-supplied assertions.

This handoff does not authenticate those assertions, notify or assign a
reviewer, grant evidence access, record a human decision, publish a finding,
or advance qualification. `verify_offline_api_review_handoff` reproduces the
whole chain and rejects changes, including JSON type substitutions.

## Planning-only attack world projection

`sunderkey.offline_api_world_projection` reproduces a synthetic API batch and
projects only corroborated synthetic signals and denied unauthorized responses
into the attack world model. Positive relations are hypotheses with zero
calibrated confidence; denials are negative observations. Review-required and
abstained cases create no graph edge. Principal and object identities are
hashed into generic node IDs, and the source case result digest remains bound
to each edge. Opposing synthetic observations for the same target, object,
action, and principal become a graph conflict, which the path query excludes.

The caller supplies observation and expiration times. Their chronology and
the batch's origin are not authenticated. The projection has no verified path,
qualification, routing, finding-publication, target, or deployment effect.
`verify_offline_api_world_projection` reproduces the source batch and graph
before accepting any supplied projection.

`append_offline_api_world_projection` can append a newly reproduced batch
projection to an immutable parent snapshot. Stable synthetic principal and
object node IDs keep their first node fact; new case edges are added through
an `ObservationDelta`. Changed node definitions, changed existing edges,
unrelated scope, and exact duplicate projections fail closed. The resulting
snapshot binds its immediate parent hash. A negative retest after a positive
hypothesis remains a conflict for review, not a verified fix or an erasure of
the earlier observation. This helper does not authenticate the caller's time
order or detect a receipt replay across separate historical batches unless
those sources are checked together by a separate custody process.
