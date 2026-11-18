# Synthetic API evidence to Army planning bundle

`sunderkey.offline_api_planning_bundle` composes five existing offline
boundaries: synthetic API case verification, attack-world projection, coverage
scheduling, capacity rehearsal, and Army v2 roster binding. The result is a
content-addressed, replayable planning bundle. It performs no target request,
credential access, specialist dispatch, finding publication, qualification, or
live authorization.

The builder requires a `VerifiedAssessmentScope`, exact synthetic batch
sources, declared capabilities and validators, explicit planning limits and
capacity slots, and the 451-profile Army v2 registry. The batch scope ID must
match the verified scope ID, and the API technique must be explicitly allowed
by that scope. Source case results and their batch are reproduced before any
graph or task proposal is accepted. The roster binding checks that each
specialist and commander are present in the same command. It does not promote
their catalog definitions to dynamic qualification.
For receipt-sourced response evidence, the recorded source scope digest must
also equal the verified signed scope digest. A matching scope ID alone is not
enough to bind the original HTTP observation to this plan.

An optional `TargetContextBundle` can bind an already parsed API specification
or source attachment. The bundle must pass its own content identity check,
have `accepted` status, and name the exact batch mission and common invocation
authority reference. Only its digest is added to the planning bundle. Its
structural facts are not treated as observed behavior, target authorization,
or evidence that a named endpoint was tested.

The bundle includes the projection, proposed schedule, capacity rehearsal,
roster binding, source batch hash, verified scope hash, optional context digest,
declared `none` effects,
and a hash of its entire canonical body. `verify_offline_api_planning_bundle`
rebuilds that complete chain from the original inputs and rejects any changed
field. A synthetic API signal remains a graph hypothesis and proposed work;
it is not exploit proof, a live action approval, or a publishable finding.
When matching positive and negative observations conflict, the schedule keeps
review and validation proposals but suppresses safe-probe and restoration
proposals for that asset.
The local retest conformance test appends a later negative case to a child
world snapshot, replans from the prior schedule, and rehearses the changed
Army workload. It preserves both observations and never infers a verified fix.

`inspect_offline_api_planning_integrity` supports an archived record when the
original response sources are no longer available. It checks the outer and
nested content identities, exact scope and snapshot links, the capacity plan,
and the retained Army catalog binding. It does not reproduce the source cases,
authenticate their origin, prove current scope or catalog status, or approve
positive use. Its report fixes `source_replay_performed` and
`positive_use_approved` to `false`. Planning for use still requires the full
source-replay verifier and separately current authority checks.

This archive path does not select or register an older finding-validator rule.
After an authorization rule or default-registry change, prior containers can
retain historical content integrity without meeting the current source-replay
contract. Current planning requires newly reproduced case and batch results
under the [current exact authorization rule](finding-validator-sdk.md), not
relabeling archived hashes or relying on a prior `verified` outcome.

This is a repository conformance path. Production use still needs authenticated
source custody, live currentness checks, qualified adapters, independent
review, deployment, and exact target authorization at every action boundary.
