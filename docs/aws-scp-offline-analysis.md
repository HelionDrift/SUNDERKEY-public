# Offline AWS Organizations SCP analysis

`sunderkey.aws_scp_analysis` provides one supplied-policy semantic algorithm
for `AOE-GC-D14-S01`, capability `army.gc.d14.s01`, vector
`AV-GC-D14-S01-01`, package `IWP2-AOE-GC-D14-S01`, wave `IW2-004`, commander
`AOE-GC-D14-CMD` and independent validator `AOE-HQ-19`. It is a partial offline
component, not a complete candidate or qualified specialist. It does not
modify the existing six reference adapters, their manifests or their goldens.

The module has no AWS client, dependency, transport, callback, credential
lookup, policy fetch, process, file operation, signing or deployment method.
It consumes explicit inert native JSON. Every effect remains `none`.

## Public inputs

```python
analyze_aws_scp(snapshot: dict, queries: list) -> AwsScpAnalysis
analyze_aws_scp_bytes(
    *, snapshot_bytes: bytes, queries_bytes: bytes
) -> AwsScpAnalysis
verify_aws_scp_analysis(
    analysis: AwsScpAnalysis | dict, *, snapshot: dict, queries: list
) -> AwsScpAnalysis
```

The snapshot has exactly `schema_version` (native integer 1),
`organization_id`, `management_account_id`, `scp_enabled` and `path`.
Management and member account IDs are explicit twelve-digit ASCII strings.
`scp_enabled` is a native bool or null; null means unavailable applicability.
The path is one supplied root, zero or more ordered OUs, then one member
account. It is not discovered or authenticated. The selected member cannot
equal the declared management account. Each level has exactly `node_id`,
`node_type`, `attachments_complete` and `policies`:

```json
{
  "node_id": "ou:workloads",
  "node_type": "ou",
  "attachments_complete": true,
  "policies": [
    {
      "policy_id": "reads",
      "document": {
        "Version": "2012-10-17",
        "Statement": [
          {"Effect": "Allow", "Action": "s3:Get*", "Resource": "*"}
        ]
      }
    }
  ]
}
```

Node IDs are unique. Repeating an attachment at one level is rejected. The
same policy ID may occur at multiple levels only with identical canonical
native content. Conflicting documents cannot be made equal by bool/int
substitution. Distinct statement Sids within a policy must be unique. Sid is
optional; redundant statements without a Sid are permitted and witnesses are
deduplicated. Completeness flags and policy IDs are declarations, not proof
of current Organizations inventory or attachment truth.

Every query has exactly these fields:

```json
{
  "query_id": "read-object",
  "principal_account_id": "222222222222",
  "principal_kind": "iam_role",
  "action": "s3:GetObject",
  "resource": "arn:aws:s3:::synthetic-bucket/reports/one",
  "context": {
    "values": {"aws:SecureTransport": "true"},
    "absent_keys": []
  }
}
```

Principal kind is `iam_user`, `iam_role`, `root`, `service_linked_role` or
`unknown`. The account can be null when unavailable. A declared account
outside the selected member path is inconclusive, not evaluated using
another account's policies. Declared management-account and service-linked
role exemptions produce `not_applicable`; they are not authenticated.
Declared disabled SCPs also produce `not_applicable`. Unknown applicability
produces `inconclusive`. Neither state is a permission grant.

Queries have unique IDs and explicit action names, not action patterns.
Resource is an explicit ARN or `*` for a declared service-wide request.
The module does not establish that an action exists or which resources and
condition keys a real service includes in one authorization request.

Context values are nonempty scalar ASCII strings. Known absence is separately
declared in `absent_keys`; an omitted key is unavailable, not absent. Keys
match case-insensitively, and case-colliding or simultaneously present/absent
declarations are rejected. Empty, multivalued or typed context datasets are
outside this input subset. Bool and Null policy values and supplied boolean
context values use the exact strings `true` and `false`, not JSON booleans.

## Semantic algorithm and uncertainty

Matching Allow statements from policies attached at one level combine by OR.
Every level must have a matching Allow; levels combine by AND. A definite
matching explicit Deny at any level overrides these allows. An empty complete
level consequently blocks in the supplied model. Incomplete attachments,
unsupported policies or unavailable matching conditions remain inconclusive
unless a known explicit denial already establishes a modeled block.

Action matching is case-insensitive and supports global `*` or a literal
service prefix with `*` and `?` in the action portion. Wildcard service
prefixes remain unsupported. Deny Resource
supports `*`, exact ARNs and `*`/`?` in the ARN's final resource segment. The
earlier five segments must be literal. Tail wildcards may span slashes. For
a queried tail containing colons, only an exact ARN or one plain trailing
`*` is evaluated; other wildcard shapes are unresolved. Patterns containing
both colons and wildcards in their tail remain unsupported. Wildcards in
earlier ARN segments also remain unsupported. These restrictions avoid
guessing segment-boundary behavior.

The initial Allow Resource subset accepts only `*`. The official SCP syntax
page's summary lists Resource for Allow and Deny while its later Resource
paragraph says Allow accepts only `*`. This component does not resolve that
documentation inconsistency into a broader grant. Other Allow Resource forms
are explicitly unsupported and remain inconclusive.

Supported scalar conditions are `StringEquals`, `StringLike`, `Bool` and
`Null`. Different operators and keys combine by AND; policy candidate values
for one key combine by OR. String comparisons are case-sensitive. StringLike
supports `*` and `?` in the policy pattern. Wildcard characters in a supplied
context value remain ordinary input characters; they do not disable or alter
the policy pattern's matching semantics. Known absent keys do not match
StringEquals, StringLike or Bool; Null evaluates declared presence versus
declared absence. Unavailable
keys remain unknown. A known false conjunct makes the whole supported
condition false even if another key is unavailable. A non-boolean supplied
string for Bool remains unknown, not silently false.

NotAction, NotResource, Principal, policy variables, unsupported versions,
unknown policy/statement fields, other condition operators, set operators,
IfExists, ARN/numeric/date/IP operators and wildcard earlier ARN segments are
not evaluated. Their source issues are retained. Unsupported statements are
not used as known grants or denials, even if some of their fields look like
a supported rule. All such source issues conservatively keep applicable
queries inconclusive unless a supported definite Deny wins. Malformed native
field types, missing selectors, contradictory selectors and invalid closed
snapshot/query shapes are rejected instead of producing a partial result.

Official primary sources inspected on 2026-09-28:

- [SCP hierarchy evaluation](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_evaluation.html)
- [SCP non-grant boundaries and exemptions](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html)
- [SCP syntax and its Allow Resource wording](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_syntax.html)
- [Condition keys](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition.html)
- [Condition operators](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html)
- [AND/OR condition composition](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-logic-multiple-context-keys-or-values.html)
- [Resource ARN wildcard semantics](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_resource.html)

## Results and exact replay

Each sorted query result has one decision: `blocked`, `inconclusive`,
`not_applicable` or `not_blocked_by_supplied_scps`. Results retain sorted
allow/deny/unresolved statement witnesses with exact node, policy and
statement-digest bindings, reasons, missing-allow levels and incomplete
levels. The summary accounts for every query. A known explicit Deny retains
both its definite witness and any independent source uncertainty.

`blocked` means a modeled SCP block, not an authenticated effective AWS
denial. `not_blocked_by_supplied_scps` never means effective access, policy
safety, finding severity or a real request's success. Identity, resource,
session, boundary and resource-control policies, live provider state and
principal authenticity remain outside this algorithm.

The frozen record owns canonical JSON text and returns detached dictionaries.
Its parsers and every export repeat the algorithm over embedded snapshot and
queries. A false result, witness, effect or summary cannot be accepted by
coherently recomputing its outer address. The explicit verifier additionally
binds separately supplied original sources. A truthful newly addressed model
is another model, not authenticated provenance or a substitution for the
original inputs.

Addresses use separate `sunderkey.aws-scp-snapshot.v1`,
`sunderkey.aws-scp-queries.v1`, `sunderkey.aws-scp-query.v1`,
`sunderkey.aws-scp-statement.v1` and `sunderkey.aws-scp-analysis.v1` domains.
These bind canonical parsed native JSON, not raw byte spelling. Whitespace
and object-key order can produce the same address; source array order remains
bound. Semantically equivalent permutations preserve decisions but may change
source, statement or report addresses. Supplied inputs are embedded without
redaction, so callers must use sanitized inert data.

## Finite bounds and acceptance

Owned native capture precedes semantic hashing and matching. The combined
input and output graphs have a conservative escaped-byte budget of 4 MiB,
24 nesting levels, 100,000 nodes and 4,096 characters per JSON string.
Semantic text fields are at most 512 ASCII characters. Shared containers are
charged for every occurrence; cycles, floats, nonfinite values, invalid UTF-8,
non-native primitive/container families and integers outside signed64 reject.
Byte intake rejects duplicate keys at all levels and checks nesting before
decoding. Schema/count fields and native bool flags do not accept equal
bool/int/float aliases.

There are at most eight path levels, 128 policy attachments across all
levels, 2,048 statements counting repeated attachments, 128 queries and
128 items per ordinary local list. Each condition has at most eight operators
and 32 keys; supplied present and absent maps each have at most 32 keys.
There are at most 2,000,000 charged matching steps and 2,048 witnesses across
the whole result. Matching has no regex or expanded pattern materialization.
Budget excess rejects, never truncates a result or claims a clean outcome.
The output graph must also fit its native budgets before canonical report
serialization and addressing. These are rejection limits, not a promise that
every simultaneous maximum produces a retained result.

Synthetic tests cover path intersections, additive attachments, ancestor
denial, conditions, applicability, uncertainty, source collisions, native
intake, finite work, exact replay and detached outputs. They prove bounded
software behavior only. They do not satisfy real-host containment,
independent qualification, operational authorization, routing or deployment.
Input ownership does not sandbox arbitrary Python code, concurrent caller
mutation, valid pre-entry substitutions or authenticated source origin.
