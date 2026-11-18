# Unsigned offline task evidence relations

This additive leaf evaluates caller-declared premises and conjunction hypotheses
over one separately supplied offline specialist task result. It does not infer
an exploit pathway, shared target, tenant, identity, packet route or real access.
Two independently supplied configurations can have identical labels or addresses
without describing the same infrastructure. No matching hypothesis becomes an
action, finding, scheduler instruction, grant or positive-use receipt.

Initial evidence is limited to existing A2.4 coordination, A2.13 evidence/reporting
and A7.4 partial offline development. Existing packages, inventory states, six
reference SDKs, D016 history and live-use gates are unchanged.

## Closed plan and fixed selection

The model contains exactly `schema_version` (native integer 1), `plan_id`,
`premises` and `hypotheses`. A premise has exactly `premise_id`, `job_id`,
`component_id`, `source_model_sha256`, `flow_id` and `expected_decision`.
The first two supported components are fixed, not dynamically imported:

- `gcp_supplied_vpc_firewall_new_flow_predicates`: expectation is
  `allow_under_supplied_vpc_predicates` or `deny_under_supplied_vpc_predicates`.
- `azure_supplied_nsg_directional_predicates`: expectation is
  `allow_under_supplied_nsg_predicates`, `deny_under_supplied_nsg_predicates` or
  `not_filtered_by_declared_nsgs`. The last value is distinctly not an Allow.

Each hypothesis contains exactly `hypothesis_id` and a nonempty `dependencies`
array. Each reference has exactly `kind` (`premise` or `hypothesis`) and `id`.
Identifiers are unique within their typed namespaces. Identical spellings in
different namespaces are unambiguous because every reference includes its kind.
Duplicate scoped references, missing references, cycles and empty conjunctions
are rejected. Forward references and shared children are supported. This is a
bounded conjunction DAG, not a reachability or dependency-execution engine.

Known contrary leaf decisions produce `contradicts_declared_expectation`.
An actual `unassessed` decision produces `unassessed`, never a desired expectation.
An exact supported expected decision produces `matches_declared_expectation`.
Conjunction has contradiction precedence, then uncertainty, then all-match.
Known actions can retain leaf uncertainty, such as incomplete GCP same-action
witness sets. Full selected leaf observations remain visible; a match does not
erase them or claim complete provider knowledge.

Original model array ordering is preserved in `source_model`. Derived premise
and hypothesis displays sort by their identities; typed dependencies have a
deterministic display order and evaluation uses a deterministic topological order.
Changing original order changes its source address even when conjunction results
do not change. Repeated sources do not become independent evidence.

## Explicit APIs and original sources

- `parse_offline_specialist_task_relations_model(content)` accepts exact bounded
  ASCII bytes and returns a detached closed plan. It has no hash, parent replay,
  catalog generation, source read or algorithm dispatch.
- `analyze_offline_specialist_task_relations(model, *, task_report, task_model,
  catalog, repository_root)` performs one current original-task replay.
- `analyze_offline_specialist_task_relations_bytes(*, model_bytes, task_report,
  task_model, catalog, repository_root)` adds bounded byte intake to that pass.
- `verify_offline_specialist_task_relations(report, *, model, task_report,
  task_model, catalog, repository_root)` requires the separate original plan and
  all separate current task inputs, comparing the complete derived report.

`OfflineSpecialistTaskRelations.from_dict` and `.from_json` require the same
separate inputs as verification. Direct wrapper construction is disabled.
`OfflineSpecialistTaskRelationsError` rejects closed inputs, finite ceilings,
source drift and inconsistent replay. Existing domain validation failures are
normalized with their cause retained. Arbitrary `TypeError` or `RuntimeError`
programming failures are not swallowed or relabeled as an input verdict.

Before calling any parent replay, the leaf bounds and owns the plan and external
input projections, checks typed references and acyclicity, and joins every
premise to its exact job, fixed component, original source and flow. Captured
leaf source content is compared with the separately supplied original request;
claimed source pins are compared without duplicating leaf hashing or dispatch.
No captured observation is consumed until the complete task is replayed against
the separately supplied task model and current catalog. The full returned OST
document must equal the captured original document, not merely its IDs/digests.
Separately owned delivery inputs preserve original caller objects.

The existing task verifier runs the inherited algorithms once per job in that
one replay. This leaf does not dispatch them again. A final catalog source check
after preparing the relation result catches demonstrated late local source
drift before relation addressing. These current-source reads are explicit
development I/O, not a filesystem containment or atomic snapshot guarantee.

The output derives exact OST, original task-model and catalog bindings. Those
moving addresses never appear in the checked static relation fixture or model.
`component_fixture()` returns a fresh plan containing stable leaf source-model
pins only. `task_fixture()` returns its fresh two-job inert task model; neither
helper produces a catalog or a task result at import time.

## Metadata export is not current verification

`to_dict()` and `to_json()` check detached native metadata, premise/status joins,
the DAG, deterministic displays, fixed effects/limits and relation addresses.
They do not read a repository or re-evaluate leaf/current-source semantics.
A coherently changed unsigned observation can describe itself as metadata; only
separate-original/current reconstruction can reject it as a substitute for the
actual task. Tests demonstrate this distinction rather than calling a digest or
wrapper authenticated evidence. Historical export can remain internally valid
after repository source drift, but current verification then fails.

The report retains the complete original relation model, selected unsanitized
leaf observations and task content identities. The full OST and original task
model are separately required inputs, not silently reduced to hash-only proof or
redundantly embedded. Labels and observations are not a sanitized, secret-free
or safe-publication artifact. No owner signature or provider truth is established.

Report identities use the `OTR-` prefix and domain
`sunderkey.offline-specialist-task-relations.v1`; ordered plan source identities
use `sunderkey.offline-specialist-task-relations-model.v1`. These are unsigned
content-integrity addresses, not authority or ongoing currentness observations.

## Finite software accounting

Limits are 32 premises, 16 hypotheses and 64 aggregate dependency references;
models/reports have 64 KiB/512 KiB canonical-byte ceilings, 8,192/65,536 native
node ceilings including keys, and scalar-inclusive depth 16. Relation strings
use printable ASCII up to 512 characters, labels up to 128, and integers exact
signed int64 before decimal conversion. Native subclasses, float aliases,
cycles, malformed integer grammar, nonfinite numbers and duplicate JSON keys
are rejected. Raw bytes, escapes, nodes, strings, depth and lexical integers are
bounded before decoding. Repeated shared subtrees are charged on each occurrence;
structural punctuation, escaped bytes and queued children count before copying.

External task models/results retain the unchanged 8 MiB, 200,000-node, depth-80
intake subset, including their Unicode scalar data. External catalog intake is
the current catalog's 1 MiB ceiling. These are explicit separate-document
ceilings, not a guarantee every
accepted parent task fits the relation operation or retained result.

One public relation pass has 128 MiB cumulative work funding its own scans,
native copying, ordering, raw allocation reservations, retained output, encoding,
comparisons and address inputs. Complete remaining relation retention, encoding
and equality passes are funded before the first **relation** digest, including
metadata exports and separate-original reconstruction. Inherited task, catalog
and leaf work use their existing separate budgets and can hash before the
relation's final own funding. This leaf does not falsely claim to meter that
inherited work or deny before every hash in the whole workflow. Each public
operation is a separate bounded pass, not global lifetime accounting.

All selected leaf rows are checked and charged before retention. Large repeated
tie-witness rows can exhaust actual result limits even when their source plan
fits. Such refusal is a software-budget failure, not a contrary hypothesis or
provider verdict. Reduced-ceiling tests also transparently prove limit placement
and exact own-work boundaries; they are not production-limit bypass claims.

All operational effects remain `none` and proof/promotion flags native false.
There is no network, target, credential, provider request, process, automatic
retry, resource discovery, routing, schedule, publication or authorization adapter.
Native detachment is not arbitrary Python isolation or a rollback guarantee.

## Development stdout-only CLI

```powershell
python scripts/run_offline_specialist_task_relations.py --plan-fixture examples/offline-specialist-task-relations.json --task-fixture examples/offline-specialist-task-relation-inputs.json
```

The CLI prints unsigned analysis to stdout. It writes no output file and grants
no operational use. Before its first composition it validates the closed plan,
DAG, original jobs, component/profile selection and unique declared flow joins.
Complete request-envelope and leaf-source arithmetic still belong to the parent;
these prechecks do not validate a declared leaf source SHA without a parent result.

The workflow performs one initial task composition followed by exactly one
inherited original/current task replay inside relation derivation. That is two
parent workflow passes, not one total algorithm call across the CLI. Relation
replay verifies the source-model digest joins and exact full task result.
