# Offline supplied AWS identity-policy and SCP pair

`sunderkey.offline_aws_policy_scp_join` composes two existing, bounded,
independently supplied analyzers for one asserted IAM user or role in one
asserted Organizations member-account path. It re-derives both analyzers from
their complete original native models. This is inert R0 policy arithmetic,
not a live AWS evaluation, effective permission, authenticated source or
authorization decision.

The component is `aws-supplied-identity-scp-pair-v1` in existing profile
`AOE-GC-D14-S01`, capability `army.gc.d14.s01`, vector
`AV-GC-D14-S01-01`, package `IWP2-AOE-GC-D14-S01`, wave `IW2-004`, commander
`AOE-GC-D14-CMD`, group commander `AOE-HQ-05` and validator `AOE-HQ-19`.
It does not create or qualify another specialist. No registered dispatcher,
provider, credential, target, file, process or network effect is added.

## Closed sources and joins

The single model has exactly five fields:

```json
{
  "schema_version": 1,
  "principal_binding": {
    "principal_ref": "principal:synthetic",
    "principal_account_id": "222222222222",
    "principal_kind": "iam_role"
  },
  "identity_model": {"...": "complete original identity-policy model"},
  "scp_snapshot": {"...": "complete original SCP path snapshot"},
  "scp_queries": [{"...": "complete original SCP query"}]
}
```

The placeholders describe shapes; they are not runnable input. Supply the
exact `identity_model` of `analyze_aws_identity_policy_set`, and the exact
`scp_snapshot` and `scp_queries` of `analyze_aws_scp`. The binding's principal
reference must equal `identity_model.principal_ref`. Its account must equal
the selected member account at the end of the SCP path. Only declared
`iam_user` and `iam_role` pairs are in this component. Every SCP query must
carry that same account and kind. Query IDs form an exact one-to-one set,
and each paired action, concrete resource ARN and complete scalar context
must be identical in canonical native JSON. Extra, missing, foreign or
changed queries refuse instead of silently re-pairing.
The minimal principal, path and request join shape is checked before either
child analyzer hashes a model. Each child then applies its own complete
schema and semantic validation; equal but malformed sources still refuse.

The identity query's `action_resource_applicability` and the snapshot's
`scp_enabled` are retained as distinct caller declarations. Neither is
inferred from an ARN, a role label or the other policy's result. A positive
pair requires true applicability, a complete supported identity set and
SCP path, an identity Allow and no modeled SCP block. Unknown
context, unsupported source semantics, incomplete attachments or unknown
applicability remain inconclusive. A declared inapplicable layer never
becomes a positive pair. A definite modeled explicit Deny, implicit missing
identity Allow and missing SCP path-level Allow remain different observations.

Each sorted result retains both underlying decisions, both query hashes,
the two applicability declarations and one pair relation:

- `explicit_deny_in_supplied_layer`
- `missing_allow_in_supplied_layer`
- `identity_allow_and_scp_not_blocked`
- `inconclusive`
- `not_applicable`

The report retains both full underlying reports with their own Allow, Deny
and unresolved witnesses. The pair relation is conditional on only these
two supplied layers. Even `identity_allow_and_scp_not_blocked` is not effective AWS
access or a recommendation: resource policies, RCPs, permissions boundaries,
session and trust policies, service-specific authorization, cross-account
logic, actual attachments, request context, principal authenticity and
current provider state are outside this component. All effects remain `none`.

## APIs, replay and costs

```python
analyze_supplied_aws_policy_scp_pair(model) -> AwsPolicyScpJoin
analyze_supplied_aws_policy_scp_pair_bytes(*, model_bytes: bytes) -> AwsPolicyScpJoin
verify_supplied_aws_policy_scp_pair(report, *, model) -> AwsPolicyScpJoin
AwsPolicyScpJoin.from_dict(document)
AwsPolicyScpJoin.from_json(raw_bytes)
record.to_dict()
record.to_json()
```

The frozen wrapper owns canonical ASCII JSON and exports detached native
data. Construction, parsing and every export re-derive both policy analyses
from embedded originals, then recompute the exact query join and result.
A coherently rehashed false pair result or child report cannot pass. The
separate verifier also requires the original complete composite model;
replacing that source with a different truthful, newly addressed model
fails original-source replay. Addresses bind canonical parsed native JSON,
not the exact input byte spelling or a signed provenance chain.

Native and byte inputs have an aggregate 512 KiB model limit, 60,000-node
and depth-16 limits, a 4,096-character per-string software subset and exact
native JSON types. The complete retained report must fit 4 MiB under the
same structural limits. There can be at most 64 paired queries. Raw input
rejects duplicate keys, floats, nonfinite numbers, oversized signed64
integers, deep structure and non-ASCII bytes. Cycles, subclasses and
bool/int/float aliases do not silently pass native capture. The two
underlying analyzers retain their own stricter semantic and work ceilings;
exhaustion refuses rather than truncating or inventing a favorable result.
These ceilings are software rejection limits, not a promise that every
simultaneous maximum fits the retained report.

The source and output are unsigned and may contain supplied policy details;
callers should use sanitized inert inputs. Ownership does not sandbox
arbitrary Python callbacks, concurrent mutation or valid pre-entry source
substitution. No publication, qualification, routing or deployment state is
changed.

Primary AWS documentation reviewed:

- [IAM policy evaluation logic](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html)
- [Organizations SCP hierarchy Allow and Deny](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_evaluation.html)
- [IAM request-context processing](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic_policy-eval-reqcontext.html)
