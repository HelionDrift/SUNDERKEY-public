# Unsigned current-source offline task delta

This additive R0 computation compares two separately supplied, currently
replayed offline specialist task results. It joins only identical caller-declared
task and job labels. A repeated label does not prove a shared target, tenant,
principal, asset or point in time. A changed request or result is not an
improvement, regression, vulnerability, finding or operational instruction.

The leaf supplies partial A2.4 coordination, A2.13 reporting and A7.4 offline
development evidence. Existing package states, current-use gates, signed
approvals, routing and qualification remain unchanged.

## Exact inputs and relation rows

`analyze_offline_specialist_task_delta` takes keyword-only `before_report`,
`before_model`, `after_report`, `after_model`, `catalog` and `repository_root`.
The byte variant substitutes exact bounded `before_model_bytes` and
`after_model_bytes`. The reports must be exact `OfflineSpecialistTaskResult`
wrappers. Both original task models must be closed native task models with
the same exact declared `task_id`, one through sixteen jobs each, and distinct
job IDs within each task. Before any full task replay, both models pass the
existing pure task-model parser. The order of the two keyword roles is the
caller declaration of a revision comparison. No extra comparison model or
catalog-derived ID is checked into a fixture.

Each task report is verified once against its separate original model and the
same current source-bound component catalog. A previously valid report bound to
an obsolete catalog is refused; this is not a historical cross-catalog audit.
The complete original report bytes and model projections are rechecked after
both replays. A final current catalog source check narrows demonstrated late
local source drift; it is not an atomic filesystem snapshot against arbitrary
concurrent replacement.

The output displays the sorted union of at most 32 declared job IDs. Each row
retains compact before/after component and profile IDs, the original selector
value or its explicit absence, complete request digest and component result
ID/digest. Relations are exactly:

- `added` or `removed` when only one supplied task contains the job label;
- `selector_changed` when explicit selector presence/value or resolved
  component/profile differs, including omitted versus explicit same default;
- `request_changed` when the selector is unchanged but the full request digest
  differs;
- `same_request` when selector and full request digest agree. Under one current
  catalog, the resulting component address must then also agree or the delta
  refuses rather than inventing nondeterministic evidence.

The original ordered task models retain their own separate OST identities.
Reordering job input can change an OST address without changing any per-job
request relation. No leaf-specific meaning is inferred from result digests.
The report contains only these identities, classification rows and fixed
none/false effects. It does not embed original source bytes, but labels and
digests are not guaranteed safe for publication or free of sensitive metadata.

## Replay and integrity

`OfflineSpecialistTaskDelta` has a disabled direct constructor and addressed
`OTD-`/`sha256:` result in the distinct
`sunderkey.offline-specialist-task-delta.v1` domain. `to_dict` and `to_json`
check detached native metadata, exact relation/count joins, fixed no-authority
fields and its local address. They do not discover or verify a current catalog.

`verify_offline_specialist_task_delta`, `OfflineSpecialistTaskDelta.from_dict`
and `.from_json` require both separate original task models and reports, plus
the current catalog and repository root. They compare the complete derived
delta, not just its address. A coherently rehashed false request/result row may
remain self-consistent unsigned metadata, but it cannot replace the current
separate-original replay. Native booleans and integers are not interchangeable.

## Finite software profile

Each external task model and report retains its existing 8 MiB, 200,000-node,
depth-80 upper intake profile; one report has at most sixteen jobs. The compact
delta report has a 512 KiB canonical-byte, 8,192-node and depth-12 ceiling.
Native input families are exact objects, arrays, Unicode scalar strings,
booleans, null and signed-int64 integers. Cycles, subclasses, float aliases,
duplicate JSON keys, oversized integers and excess escaped text refuse.
Raw report bytes, node/depth/string and integer grammar are bounded before
JSON decoding; repeated native shared subtrees are charged per occurrence.

Each delta public operation has one 128 MiB cumulative budget for its own
native scans, copying, retained rows, encoding, comparison and delta address
input. Complete own final report/equality/export work is reserved before the
first **delta** digest. The inherited task-model parser, two full task replays,
catalog reconstructions and leaf algorithms have their existing separate
budgets and can hash before the delta's first digest. This module does not
pretend to meter or pre-fund those inherited operations. The byte entrypoint
adds exact source-model byte intake to its one own budget. A source that fits
the parent task ceiling is not guaranteed to fit this delta operation.

This is a pure local classification. It has no network, process, provider,
credential or target callback, no scheduler, no state mutation or rollback,
and no positive-use, clinical, authentication or deployment authority.
