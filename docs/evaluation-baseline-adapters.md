# Evaluation Baseline Replay Adapters

This repository-only increment implements roadmap work item WQ-006. It can
replay caller-supplied baseline observations for deterministic rules, stored
model snapshots, strategy variants, and human reference inputs. Replay means
verification and content-addressed packaging. It does not mean execution.

## Boundary

The module does not discover files, resolve credentials, call a provider,
execute a model, invoke a tool, start a process, contact a target, or access a
network. It has no fields for endpoints, credentials, command lines, or target
locations. Exact-field parsing rejects attempts to add them.

Every observation and replay envelope declares these effects as `none`:

1. authorization
2. credential access
3. evaluation execution
4. filesystem discovery
5. model calls
6. network activity
7. process execution
8. provider calls
9. qualification
10. target actions
11. tool calls

The qualification effect is always `none`. A replay envelope is evidence for
repository behavior only. It cannot promote or qualify a candidate.

## Adapter families

The contract supports four provider-neutral families:

| Adapter family | Allowed baseline role | Caller-supplied input |
| --- | --- | --- |
| `deterministic_rules` | `deterministic` | Output captured from an exact deterministic rule revision |
| `stored_model_snapshot` | `generalist`, `prior_release` | Output captured from an immutable model snapshot |
| `strategy_variant` | `generalist`, `prior_release` | Output captured from an exact strategy or orchestration revision |
| `human_reference_input` | `generalist` | A content-addressed human reference artifact |

The candidate role is intentionally excluded. These adapters construct
comparison baselines, not candidate observations.

## Exact observation binding

Each baseline observation binds all of the following:

1. adapter family and baseline subject role
2. subject identifier, digest, and owner identity
3. corpus partition, case identifier, and case digest
4. model, rule, strategy, or reference implementation identifier
5. immutable implementation revision and digest
6. prompt digest and policy digest
7. expected output digest and optional observed output digest
8. an explicit `tools_allowed: false` control
9. maximum budget and observed usage for cost, latency, requests, tokens, and tools
10. contamination status, evidence digest, checker identity, and check time
11. independent evaluator identity
12. source artifact, source digest, custody manifest, producer identity, and capture time
13. exact scoring source values for a completed observation

Moving revisions such as `latest`, `main`, and `head` are rejected. Tool usage
must be zero even when the shared evaluation budget reserves a positive tool
ceiling for structural compatibility.

## Identity separation

The evaluator cannot be the baseline owner or the source artifact producer.
The replay controller must also be separate from the owner, producer, and
evaluator. This prevents a baseline subject from producing and evaluating its
own replay evidence under the same identity.

## Availability and failure

The status vocabulary preserves three different outcomes:

| Baseline status | Meaning | Scoring runtime mapping |
| --- | --- | --- |
| `completed` | A captured output and complete metric source values are present | `completed` |
| `failed` | The baseline ran or was assessed but did not complete successfully | `failed` |
| `unavailable` | No baseline result was available for this case | `abstained` |

An unavailable baseline cannot claim output, usage, or scoring values. A failed
baseline may preserve an observed output digest and usage, but cannot claim
completed scoring values. This distinction keeps missing baseline coverage
separate from an observed execution failure.

## Contamination handling

Contamination is preserved as `clean`, `unknown`, or `contaminated`. Only a
clean observation may be converted directly to the scoring runtime's
`ScoredObservation` type. Unknown or contaminated observations remain valid
replay records, but their scoring import state is
`blocked_contamination`. This prevents a lossy conversion from discarding the
attestation.

## Compatibility

`BaselineObservation.to_scored_observation()` produces the existing scoring
runtime type without executing anything. The mapping preserves case, subject,
partition, evaluator, budget, metric values, and evidence identity. The
content digest of the baseline observation becomes the scoring evidence
manifest digest.

Completed, failed, and unavailable baselines map to completed, failed, and
abstained scoring observations respectively. The fixed runner and scorecard
layers can therefore consume baseline evidence through their existing
contracts after all independent governance requirements are met.

## Tamper resistance

The observation and envelope use separate domain-separated SHA-256 identities.
Parsing recomputes both identities and rejects a changed field at any level,
including provenance, status, budget, contamination, prompt, policy, and
output digests. Parsers require exact fields. Canonical JSON import also
rejects alternate formatting so one document has one serialized identity.

Observation and envelope mapping parsers require a native integer schema
version. Boolean or float values equal to that version are rejected, including
the nested observation in an envelope. Mapping import cannot normalize these
malformed versions into an apparently valid replay. Valid native JSON keeps
the same observation and envelope identities.

The Draft 2020-12 schema provides portable structural validation. Python
validation adds cross-field checks for role compatibility, identity
separation, contamination context, budget ceilings, status semantics, and
content identities.
