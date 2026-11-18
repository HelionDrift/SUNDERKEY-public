# Supplied AWS identity-policy-set analysis

`sunderkey.offline_aws_identity_policy_analysis` evaluates a finite union of
explicitly supplied identity policies for one declared principal and concrete
action-resource queries. It performs no AWS request, policy acquisition,
credential lookup, process, network, file operation, signing or authentication.
Results describe supplied assertions, not effective AWS permission or a real
provider grant or denial.

This partial component uses `aws-identity-policy-set-v1`, existing specialist
`AOE-GC-D14-S01`, capability `army.gc.d14.s01`, vector `AV-GC-D14-S01-01`, package
`IWP2-AOE-GC-D14-S01` and wave `IW2-004`. Its commander is `AOE-GC-D14-CMD`, group
commander `AOE-HQ-05`, independent validator `AOE-HQ-19`, and blueprint digest
`sha256:b78ed5726b54b4189b10890e3ac8e0b3ba10d6341513a23c1761a952d6f1fad5`.
The approved D016 amendment permits this inert implementation and synthetic
tests; it does not alter original strategy, six reference SDKs, manifests,
real-host containment, qualification, routing, live entry or deployment gates.
Existing C4.6 status is not promoted. No new expert or qualified capability is
created. The existing Organizations SCP algorithm and provider-neutral identity
graph remain separate and unchanged.

## Exact inputs and APIs

```python
analyze_aws_identity_policy_set(model) -> AwsIdentityPolicyAnalysis
analyze_aws_identity_policy_set_bytes(*, model_bytes: bytes) -> AwsIdentityPolicyAnalysis
verify_aws_identity_policy_analysis(report, *, model) -> AwsIdentityPolicyAnalysis
```

The root has exactly these five native JSON fields:

```json
{
  "schema_version": 1,
  "principal_ref": "principal:synthetic",
  "attachments_complete": true,
  "policies": [
    {
      "policy_id": "reads",
      "document": {
        "Version": "2012-10-17",
        "Statement": [
          {
            "Effect": "Allow",
            "Action": "s3:Get*",
            "Resource": "arn:aws:s3:::synthetic-bucket/public/*"
          }
        ]
      }
    }
  ],
  "queries": [
    {
      "query_id": "read-one",
      "action": "s3:GetObject",
      "resource": "arn:aws:s3:::synthetic-bucket/public/one",
      "action_resource_applicability": true,
      "context": {"values": {}, "absent_keys": []}
    }
  ]
}
```

Every policy is an asserted attachment to the root's one `principal_ref`.
There is no principal resolution, membership expansion or attachment proof.
Policy IDs and query IDs must be unique. Statements may have an optional
nonempty `Sid`, unique within their own policy. Source array order remains
bound; witness and result ordering is deterministic.

Queries contain one concrete service/action and a basic six-part ARN value,
not wildcard actions, wildcard resources, variables or service-wide query `*`.
ARN syntax here does not prove resource existence, service support or policy
applicability. `action_resource_applicability` is a native bool or null:
caller-declared false produces `not_applicable`; null produces `inconclusive`.
True asserts applicability only for this one pair. No service catalog,
dependent resources, multiple-resource operation or provider truth is inferred.
In particular, NotAction does not derive applicable services from an ARN's
service text. [AWS NotAction scope](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notaction.html)

Context has exactly `values` and `absent_keys`. Values are nonempty scalar
printable ASCII strings. Explicit absence is distinct from an omitted,
unavailable key. Context keys compare case-insensitively, with duplicate case
variants and conflicting present/absent declarations rejected. Empty,
multivalued, numeric and boolean context datasets are outside this input
subset. No request context is authenticated.

## Policy subset and conservative uncertainty

A policy document requires a bounded nonempty native `Statement` list. Optional
`Id` is retained as source metadata. A single-object Statement, missing or
contradictory action/resource selectors, malformed Effect and unsupported native
field families are refused as outside this software input subset, not declared
universally invalid AWS policy documents.

Only `Version` equal to `2012-10-17` supports a definite witness. Missing or
null Version is retained as unavailable; another version is retained as
unsupported. Nothing is silently changed to a supported version. Unknown
document or statement fields, Principal/NotPrincipal, variables and unsupported
operators or patterns remain captured source issues. An unsupported statement
contributes no definite Allow or Deny witness. A separate fully supported Deny
can still establish a modeled identity denial, with other uncertainty retained.

Statements require `Effect` equal to Allow or Deny, exactly one of Action and
NotAction, and exactly one of Resource and NotResource. Selector values can be
a nonempty string or bounded nonempty string list. Matching allows union across
identity attachments. A definite matching explicit Deny overrides this union.
No match in a complete supported set is modeled implicit denial. Missing
attachments or unresolved statements conservatively produce inconclusive
results even when another Allow matches. The union is not the SCP hierarchy
intersection or an effective AWS decision. Resource, session, boundary, SCP,
RCP and cross-account policies are not composed.
[AWS policy evaluation](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html)

Action supports global `*` or a literal service prefix and action-name `*`/`?`
patterns, case-insensitively. Wildcard service prefixes remain unsupported.
Each selector list combines by OR. NotAction and NotResource complement that
OR result, not an OR of individual exclusions; unavailable matching remains
unavailable after negation. A Deny exception is not a grant.
[AWS Action](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_action.html),
[AWS NotResource](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notresource.html)

Resource matching is case-sensitive. Supported patterns are global `*`, exact
ARNs, and `*`/`?` in a colon-free final resource tail with the first five segments
literal. Tail globs can span slashes. For a query tail containing colons, only
an exact ARN or one plain trailing `*` is evaluated. Other wildcard shapes,
wildcards in earlier segments, and a pattern combining colons and wildcards
inside its tail are unresolved. This is a conservative software subset, not
full AWS ARN wildcard behavior. A supported selector can still be unresolved
for a particular colon-bearing query; its complement never turns that into a
known match. [AWS Resource semantics](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_resource.html)

## Scalar conditions

The finite operators are StringEquals, StringEqualsIgnoreCase, StringLike,
StringNotEquals, StringNotLike, Bool and Null. StringEquals is literal and
case-sensitive, including strings containing `*` or `?`. StringLike interprets
those characters only in policy patterns; characters in a context value remain
ordinary input. StringEqualsIgnoreCase ignores ASCII case.

Different keys and operators combine by AND. Positive candidate arrays combine
by OR; negated arrays combine by NOR. Known false conjuncts dominate unknown
context. A known absent key makes a supported positive comparison false and a
supported negated comparison true; unavailable context remains unknown. Null
tests explicit presence or absence. Bool and Null candidates are the exact
strings `true` and `false`. A nonboolean string used as Bool context remains
unknown, not silently false. No actual boolean property is established.
[AWS condition operators](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html),
[AWS condition composition](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-logic-multiple-context-keys-or-values.html)

Set operators, IfExists, ARN, numeric, date and IP comparisons, policy variables
and multivalued or empty context datasets are not evaluated. Omission does not
prove absence. Service-specific condition-key availability and operator support
are not acquired or authenticated.
[AWS condition keys](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition.html),
[AWS service authorization catalog](https://docs.aws.amazon.com/service-authorization/latest/reference/reference_policies_actions-resources-contextkeys.html)

## Owned results, replay and finite costs

Decisions are `allowed_by_supplied_identity_policies`,
`explicit_denial_by_supplied_identity_policies`,
`implicit_denial_by_supplied_identity_policies`, `inconclusive` or
`not_applicable`. These are supplied-model observations, never a real grant or
denial, authenticated finding or actual request outcome. The report retains
exact model, query, policy and statement hashes, source issues, matched Allow
and Deny witnesses, unresolved witnesses, reasons and complete summary counts.

`AwsIdentityPolicyAnalysis` owns canonical ASCII JSON and exports detached
native dictionaries. Every reconstruction/export replays the algorithm over
the retained source. False outcome, trace, witness, flag, bounds or summary
cannot pass by coherently rehashing the outer report. The explicit verifier
separately compares a complete re-derived report from the original supplied
model. Self-consistency is not authenticated source origin: a truthful different
model can have a different valid report but cannot replace that original input.
Native array order remains bound; JSON whitespace and object key order do not.

Software ceilings are 2 MiB canonical escaped bytes for each captured model or
complete report, 25,000 visited nodes, depth 16, 512 printable ASCII bytes per
string, 64 policies, 512 total statements, 64 queries, 32 selectors or candidate
values, 32 combined present/absent context keys, eight condition operators,
1,000,000 charged matching steps and 1,024 total retained witnesses. The report
contains its source, so that complete combined graph must fit the same byte and
node ceilings. Simultaneous maxima need not fit every aggregate limit.

Repeated containers and structural/escape bytes are charged before copying or
hashing; cycles, native subclasses, floats, oversized integers and scalar type
aliases refuse. Native integer magnitude is at most 2^63 - 1. Raw intake checks
byte length, nodes, depth, decimal grammar and magnitude, scalar length and
escapes before decoding; duplicate members reject before semantic hashing.
Report counters and flags retain exact native types. Bounded glob matching
does not use regex pattern expansion. Source digests are computed once per
source, not once per query witness. Budget exhaustion rejects instead of
truncating or publishing an optimistic conclusion.

Authority, target, execution, routing, qualification, deployment, network,
provider, credential and process effects remain `none`. Authentication,
applicability truth, effective access, live approval and qualification flags
remain false. There is no signer, trusted clock, replay guard, provider port,
credential resolver or runtime admission path. Ownership does not sandbox
arbitrary Python code, concurrent caller mutation, valid pre-entry substitutions
or rollback. Supplied source contents are retained without redaction, so callers
must provide appropriately inert or sanitized input.

Synthetic tests use public supplied documents, independent finite wildcard and
identity-decision oracles, explicit complement and condition controls, native
cost boundaries, readdressed false results and original-model substitution.
They establish finite local software behavior only. Official primary sources
linked above were inspected on 2026-09-28.
