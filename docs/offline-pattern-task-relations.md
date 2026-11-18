# Supplied Pattern Task Relations

The offline relation composer binds explicit reviewer hypotheses to selected
projections from one separately supplied, current-source-replayed specialist
task. The fixed set covers all sixteen `AOE-GE-D23-S01` through `S16`
profiles, including serialization, JSON key policy, archive paths, DNS scope,
authorization, session, origin, check-use, resource budget, dependency
fallback, configuration, deputy, integrity, and input and output discrepancy
declarations. Their different result shapes retain fixed selectors.
A plan selects each job, component, original source digest,
projection ID, and expected disposition. It requires at least two distinct
jobs and specialists.

The plan contains an exact scope binding whose only accepted basis is
`caller_declared_unverified`. The binding names exactly the jobs used by its
premises. No matching labels or results establish that the jobs describe one
target, principal, application, time window, or exploit path. The result
reports whether each selected leaf disposition matches, contradicts, or is
unresolved relative to the declared expectation. Contradiction takes
precedence over unresolved in the aggregate review status.

Analysis and verification require a separate original plan, original task
model, current component catalog, and exact task-result wrapper. The task is
replayed against current leaf sources before any projection is selected.
Changing an original source, selected projection, expectation, or task report
requires a new relation result. Exporting an existing report is not current
verification. The static [synthetic plan](../examples/offline-pattern-task-relations.json)
contains no dynamic task or catalog identity; its three source digests bind
the corresponding inert examples.
The [expanded six-source plan](../examples/offline-pattern-task-relations-expanded.json)
adds the configuration, deputy, and integrity examples under the same
caller-declared, unverified scope boundary. It does not add a live chain.
The [twelve-source plan](../examples/offline-pattern-task-relations-twelve.json)
adds the remaining six common-task specialists. Its authorization premise
selects an exact three-field comparison key by the SHA-256 digest of the
canonical `principal_ref`, `action_ref`, and `resource_ref` map. This digest
identifies a supplied comparison, not a verified principal or common target.
The [sixteen-source plan](../examples/offline-pattern-task-relations-sixteen.json)
adds the four previously separate cross-surface jobs. Pickle uses its source
review disposition, JSON selects a field name, archive selects an entry ID,
and DNS selects an exact snapshot-pair digest. Each selection remains bound
to its own original model and replayed leaf result, not a common target.

The fixture command reads a bounded local plan and separate original task,
prejoins the declared job, component, and source digests before loading the
catalog, and prints one complete result only after composition and replay:

```sh
PYTHONPATH=src python scripts/run_offline_pattern_task_relations.py \
  --plan-fixture examples/offline-pattern-task-relations.json \
  --task-fixture examples/offline-pattern-task-inputs.json
```

It has no output-file option. A malformed plan or changed original source
produces no partial stdout result. The command does not authenticate its
input files or convert the report into a positive-use artifact.

To check a separately saved JSON result, add
`--verify-report-fixture path/to/relation.json` to the same command. The
bounded reader rejects linked, oversized, malformed, or duplicate-member
JSON before replay. Verification reconstructs the original task and current
catalog, then requires the exported report to match the new complete result.
A copied report is not self-verifying; a successful local replay remains
unsigned and does not authenticate input provenance or permit action.

The native plan is limited to 16 premises and 32 KiB, with a 128 KiB report
bound. No query, command, code, template, payload, target response, credential,
network destination, or target action is processed. The unsigned result keeps
scope equivalence, source authentication, candidate assembly, positive-use
approval, and qualification false. Every operational effect remains `none`.
