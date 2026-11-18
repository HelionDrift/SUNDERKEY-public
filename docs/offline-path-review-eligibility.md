# Offline Path Review Eligibility

`offline_path_review_eligibility.py` is a fail-closed, repository-only contract
for deciding whether a supplied path may be put before independent reviewers.
It does not promote a fact into the attack world model, make a finding eligible
for publication, authorize an action, or establish live or production evidence.
Its positive result is explicitly conditional on a caller-injected verifier.

## Candidate and Proof Boundary

A candidate binds one tenant, exact context and scope digests, and a declared
evaluation time. Its ordered path has two to eight distinct nodes, one proof
for every node, and one proof for each contiguous directed edge. Every proof
must refer to one exact observation with a matching node or edge claim. Thus
the entry, objective, every intermediate hop, and every transition are covered.
No missing, repeated, or unbound proof can enter a positive packet.

An observation must declare the exact
`independently_authenticated_observation` class, source digest, complete
source lineage, producer, tenant, context, scope, observation time, and expiry.
Operator-supplied records, offline specialist leaves, uncertain or contrary
observations, future observations, and evidence stale at the declared time are
rejected. This module does not authenticate the source class or the clock by
itself. The injected verifier must independently check the underlying signed
observation, its complete conflict-free lineage, source origin, and trusted
time before returning its bound receipts. A caller can backdate
`evaluated_at`; local timestamp comparisons alone therefore do not establish
freshness. The injected time verifier must check a current trusted window and
return a receipt bound to both the exact candidate body and evaluation time.

Two accepting reviews are required, one Control and one Assurance. They must
bind the exact candidate body, occur after its observations and no later than
the declared evaluation time, use distinct reviewer identities, and be
separate from every observation producer. The injected verifier must check
each underlying decision and reviewer identity. A self-declared review record
alone is insufficient.

## Injected Verifier Contract

`evaluate_path_review_eligibility(candidate, verifier)` calls four methods:

- `verify_time(candidate_body_sha256, evaluated_at)` first. Its receipt must
  bind both arguments, an exact `within_trusted_current_window` decision, and
  verifier ID. Missing, backdated, out-of-window, or substituted decisions
  fail closed. The caller must supply a verifier backed by a real trusted time
  source; this module does not provide one.
- `verify_observation(observation, candidate_body_sha256, evaluated_at)` for
  each path proof. Its receipt must bind the proof ID, source digest, candidate
  body digest, independently authenticated class, accepted result, and
  verifier ID.
- `verify_lineage(observations, candidate_body_sha256, evaluated_at)` once.
  Its receipt must bind the exact complete sorted source-lineage digest set,
  candidate body digest, `complete: true`, `conflict_free: true`, and verifier
  ID. It must detect relevant counterevidence omitted from the candidate.
- `verify_review(review, candidate_body_sha256, evaluated_at)` for each review.
  Its receipt must bind review ID, reviewer ID, role, candidate body digest,
  accepting decision, and verifier ID.

Bare booleans, extra fields, and receipts with a wrong type or binding are
rejected. The module has no trust roots, signature keys, source repository,
trusted clock, or reviewer directory. It cannot establish that an arbitrary
caller-supplied verifier is genuine. A fake verifier can only produce a
conditional local packet, never independently proved trust or live use.
Production consumers must separately select and authenticate their verifier
and recheck current authority and source evidence. The synthetic verifier in
the tests is intentionally nonqualifying.

The returned packet binds exact verifier receipts and the candidate digest.
`verify_path_review_eligibility(packet, candidate, verifier)` rebuilds it from
the separately retained original candidate and fresh verifier decisions,
then rejects changed, rebound, or stale packets. Historical hash agreement
alone is not current verification.

## Example and Effects

`examples/offline-path-review-eligibility.json` is a synthetic candidate
shape with locally generated digest references. It is not authenticated
evidence. It can be exercised only with a separately injected test verifier;
the repository does not supply a qualifying verifier implementation.

The only positive packet status is
`conditional_review_eligible_under_injected_verifier`. It fixes
`world_edge_promotion` and `finding_eligibility` to `none`, declares verifier
trust unestablished by this module, and fixes all operational effects to
`none`. It must never be used as an action, qualification, finding-publication,
or target-access credential.

Focused test command:

```text
python -m unittest tests.agents.test_offline_path_review_eligibility -v
```
