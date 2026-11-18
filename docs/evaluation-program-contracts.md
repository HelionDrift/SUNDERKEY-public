# Evaluation Program Contracts

This increment supplies the repository-only measurement and corpus governance
contracts for roadmap packages R0.3, R0.4, E3.2, E3.3, E3.5, and E3.6. It
defines what a controlled evaluation must bind before any runner or scoring
service is allowed to operate. It does not execute an evaluation and does not
claim that any package is operationally qualified.

## Scorecard

The contract requires all eleven measures from the capability roadmap:

1. ground truth recall
2. validated finding precision
3. validator reproduction rate
4. attack path depth
5. unauthorized target actions
6. cleanup completion
7. time to first verified finding
8. cost per verified finding
9. run to run stability
10. evidence completeness
11. customer remediation acceptance

Every metric declares its direction, unit, numerator, denominator, immutable
denominator source digest, minimum denominator, zero-denominator treatment,
pass threshold, critical threshold where applicable, and critical gate
bindings. Missing observations, failed cases, and abstentions stay in the
fixed denominator. Post-run case exclusion and duplicate evidence cannot
improve a score.

The eight critical failure gates from qualification standard version 2 are
hard stops. They cannot be averaged into a weighted composite, and the
maximum permitted critical failure count is zero. Unauthorized actions and
incomplete cleanup have explicit hard thresholds.

## Corpus partitions

Every corpus release contains exactly these partitions:

- public
- private holdout
- adversarial safety
- regression
- pilot

Each partition binds an exact suite version, content digest, manifest digest,
provenance digest, membership commitment, case count, ground-truth digest, and all six
specialist scenario variants. The six variants cover positive reproducibility,
negative controls, ambiguous authority, adversarial evidence, collaboration
conflicts, and restoration verification.

Non-public suites use opaque `vaultref:` references. The contract cannot carry
inline private cases or private ground truth. Public content uses an
`artifactref:` reference. A digest is an integrity binding, not permission to
retrieve the referenced content.

Every partition requires a contamination check for the candidate. Every pair
of partitions requires a zero-overlap attestation from the ground-truth
custodian. A contaminated candidate, nonzero overlap, missing attestation, or
private holdout exposure to the candidate blocks construction. Blind
evaluators may receive private metadata but not private content.

## Separation of duties

The following identities must all be distinct:

- candidate
- corpus custodian
- ground-truth custodian
- execution controller
- plan author
- each independent evaluator

At least two evaluators are required. Each receives a content-addressed blind
assignment by opaque reference. The assignment exposes neither subject roles
nor private partition references. Evaluators cannot own an evaluated subject,
and the candidate must own the candidate subject binding.

Four subjects are mandatory: deterministic baseline, generalist baseline,
prior release, and candidate. Their exact versions, artifacts, and
configurations are pinned. Moving labels such as `latest`, `main`, and `head`
are rejected. The capability roadmap, evaluation policy, qualification plans,
qualification standard, and specialist scenario corpus also require exact
version and digest pins.

## Evaluation plan

The embedded plan is always `planned_non_executing` and its result claim list
must be empty. Its budget must cover every corpus case, and its request and
token ceilings must be internally consistent. The comparison policy requires
same-case, same-budget paired comparisons against all three baselines, three
repeated runs, Holm-Bonferroni correction, fail-closed missing observations,
hard-stop critical gates, and no weighted composite.

The contract explicitly records no authorization, corpus download, evaluation
execution, model call, provider call, network activity, qualification, or
routing effect. A later execution system must separately authorize and record
those effects.

## Verification

`EvaluationProgramContract.from_json` and
`verify_evaluation_program_contract` rebuild every invariant and the
content-addressed identity. The strict JSON Schema at
`registry/schemas/evaluation-program-contract-v1.schema.json` provides a
portable structural check. Python verification remains authoritative for
cross-record uniqueness, identity separation, partition pairing, secrecy,
anti-gaming, and content identity rules that JSON Schema cannot fully express.

This increment establishes definitions and governance only. Corpus creation,
private storage, range deployment, evaluator credential issuance, runner
execution, scoring, statistical review, and qualification decisions remain
external or later work.
