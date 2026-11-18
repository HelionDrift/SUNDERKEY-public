# Bounded offline specialist task composition

This leaf groups separately supplied inert inputs under one unsigned task label.
It runs actual heterogeneous algorithms through the existing closed dispatcher,
retains every complete result and reports the existing catalog's package,
commander and independent-validator ownership. It does not assemble a candidate,
route a task, appoint a reviewer, publish findings or grant positive-use authority.
The original six-reference SDK, signed domains and qualification gates are unchanged.

A synthetic five-profile software supply-chain regression combines build-run,
repository-secret, IaC, development-container and vendor-update metadata in
one task. Each leaf retains its original source and owner. The composition
does not establish that the records refer to one target, one incident or one
validated path.

## Explicit model and API

The closed native model has exactly `schema_version: 1`, `task_id`, and `jobs`.
Each of 1 through 16 jobs has exactly `job_id` and a complete existing component
`request`. Task and job identifiers are bounded ASCII labels; job IDs are unique.
Requests preserve their original fields, array order, embedded source text and
omitted versus explicit component selectors. Every request must independently
pass the existing R0, dry-run, no-credentials and deny-all-resource envelope.

`run_offline_specialist_task(model, *, catalog, repository_root)` returns a frozen
`OfflineSpecialistTaskResult`. `run_offline_specialist_task_bytes(*, model_bytes,
catalog, repository_root)` accepts bounded UTF-8 JSON instead. The separate
`parse_offline_specialist_task_model(content)` only validates and detaches the
closed task model. `load_offline_specialist_task_model(path)` uses the existing
bounded local regular-file development reader, not a runtime filesystem grant.
No repository, identity or credential is implicitly discovered.

Before the first analyzer runs, every job passes
`prepare_offline_specialist_component_request` with the current catalog. This
shared preflight validates the original envelope, registered selector and
top-level payload shape, not complete leaf semantics. A later invalid resource,
credential, callback field or selector therefore denies before any analysis.
A later leaf-semantic failure may follow earlier pure calculations; no partial
task result is returned. Existing leaf `ValueError` validation failures are
normalized at the single dispatch boundary to `OfflineSpecialistTaskError`,
with the original cause retained and no raw source in the task error message.
This does not swallow arbitrary programming exceptions. There is no retry,
fallback or output-to-input wiring.
One analyzer invocation per job occurs in each composition or explicit replay
pass, not once across the lifetime of all report operations.

Results display jobs in job-ID order while retaining the original ordered model.
Reordering original jobs changes its source digest and task address even when
the individual calculations are identical. Repeated sources may share result
addresses; job counts and distinct profile/component counts are not independent
observations, distinct targets or qualification evidence.

## Integrity, current sources and retained content

The result includes complete component results and a simple ownership index,
the original model, its canonical native digest, the current catalog ID/digest,
fixed none effects and false promotion flags. The task address uses the distinct
`sunderkey.offline-specialist-task-result.v1` domain and `OST-` prefix. This is
unsigned content correlation, not independent authenticity, source truth or a
shared target/principal/tenant relationship.

`verify_offline_specialist_task(report, *, model, catalog, repository_root)`
recomputes against separately supplied original inputs and current source-bound
catalog content. `OfflineSpecialistTaskResult.from_dict` and `.from_json` require
those same explicit arguments. Coherently rehashed false conclusions cannot
replace source replay. Every composition and replay rechecks current catalog
bindings before returning a completed result. No historical stale-catalog
fallback exists, and this is not an atomic filesystem snapshot against arbitrary
concurrent replacement.

`to_dict()` and `to_json()` return detached, bounded metadata and check its local
addresses and self-contained joins. They do not discover a repository, run
algorithms or establish current-source verification. A wrapper or digest alone
is not verified use. The public raw wrapper constructor is disabled in favor of
composition and explicitly source-replaying parsers. These checks do not sandbox
arbitrary Python code or authenticate any injected implementation.

Complete requests and results retain unsanitized supplied source content.
The report is not redacted, secret-free, safe to render, or an opaque-content
classification. Callers must choose suitable inert inputs and handle retained
metadata under their own disclosure rules. No result is converted into a
finding, admission receipt, action intent or authenticated commander handoff.

## Software-cost boundaries

Model and completed result each have an 8 MiB canonical JSON ceiling. Each native
document has at most 200,000 nodes including object keys and at most depth 80;
only exact native objects, arrays, Unicode scalar strings, booleans, null and
full signed-int64 integers are supported. Aliases, subclasses, floats, nonfinite
numbers and duplicate JSON keys are rejected. Raw-byte, escaped-string, scalar,
node and depth ceilings are checked before JSON decoding. Native shared subtrees
are charged on every occurrence before serialization, not deduplicated by object
identity. No oversized integer is converted before its lexical bound.

Each public pass has a 128 MiB cumulative orchestration-work budget. It charges
own native/string traversal, copying, JSON scans, serialization and digest bytes;
it does not claim to count internal catalog reconstruction or leaf algorithm
work, which retain their separate existing limits. There are at most 16 explicit
preparation calls and 16 analyzer calls per pass. All cumulative retained-output
bounds and the remaining final serialization/address work are reserved before
the task's source/result digests. Leaf algorithms may already have computed their
own bounded results before an aggregate task output limit denies publication.
An input within the intake ceiling is not guaranteed to fit the completed result.
Export operations enforce their own bounded metadata-validation budget.

This composition is partial offline evidence for existing mission coordination
and evidence/reporting work. It changes no completion, parity, readiness,
independent acceptance, activation, runtime safety or deployment state.
