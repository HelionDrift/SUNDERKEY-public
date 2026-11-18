# Supplied GCP allow-policy analysis

This partial offline algorithm evaluates exact supplied permissions and allow
bindings over a declared organization, folder, project and service-resource
ancestry. It belongs to `AOE-GC-D14-S06`, capability `army.gc.d14.s06`, vector
`AV-GC-D14-S06-01`, wave `IW2-009` and existing package `C4.6`. It is not a full
specialist implementation, effective-access decision or qualified component.

The module has no GCP client, discovery, credential handling, network, process,
callback or file I/O. All authority, execution, target, provider, credential,
qualification, routing and deployment effects remain `none`.

## Public interface

`analyze_gcp_iam(snapshot, queries)` accepts native dictionaries and lists.
`analyze_gcp_iam_bytes(*, snapshot_bytes, queries_bytes)` accepts separate bounded
ASCII JSON byte strings. `verify_gcp_iam_analysis(report, *, snapshot, queries)`
recomputes against separately supplied original inputs. The frozen
`GcpIamAnalysis` provides `from_dict`, `from_json`, `to_dict`, `to_json`,
`analysis_id` and `analysis_sha256`. Each export repeats embedded-input replay
and returns detached native data.

The closed snapshot contains:

- `schema_version`: exact integer `1`.
- `resources`: unique rows with `resource_name`, `kind` and nullable
  `parent_resource_name`. Kinds are `organization`, `folder`, `project` and
  `resource`. A supplied project can be a standalone root. Folder parents must
  be organizations or folders; project parents must be organizations or folders;
  service-resource parents must be projects or other service resources.
- `roles`: unique `name`, exact `included_permissions`, explicit `stage`,
  `deleted` and `permissions_complete`. Stages are `ALPHA`, `BETA`, `GA`,
  `DEPRECATED`, `DISABLED`, `EAP` or `unknown`.
- `allow_policies`: unique `resource_name`, version `1` or `3`, nullable `etag`
  and `bindings`. Each binding has exact `role`, unique nonempty `members` and
  nullable `condition`. A condition has `title`, `description` and `expression`;
  an explicit condition requires version `3`.
- `coverage`: explicit boolean `resource_ancestry_complete` and
  `allow_policies_complete`, plus `deny_policies` and
  `principal_access_boundaries`, each `none_supplied`, `present` or `unknown`.

Each query contains unique `query_id`, `resource_name`, exact `permission`,
`principal`, unique active `groups` and boolean `group_membership_complete`.
These are normalized supplied declarations, not an unrestricted parser for
every Google API response. Exact case and spelling are preserved.

`component_fixture()` in the test module returns a complete synthetic snapshot
and queries with a folder-inherited group allow, sibling no-match and conditional
service-account uncertainty. It contains no credentials or authentication keys.

## Supported reasoning and uncertainty

Allow permissions are additive over the supplied ancestry. Exact permission
membership is used, with no wildcard expansion or role-name inference. An
organization or project custom role must have its owner in the binding's policy
resource ancestry, not merely in the queried resource ancestry. Disabled or
deleted roles contribute no witness. Unknown lifecycle or missing role contents
remain unresolved; incomplete role contents retain known inclusions but do not
prove an absent permission.

Direct active user and service-account members and explicitly supplied active
group membership are supported. Email aliases, case folding, domain expansion,
public members and workforce/workload identity selectors are not inferred.
Deleted members with numeric `?uid=` remain deleted and are never stripped into
active principals. Unsupported selectors are unassessed when they could matter.

No CEL expression is evaluated, including the text `true`. A role containing
`_withcond_` is guarded before role lookup and never stripped: version `1` can
hide a condition this way. This conservative subset also leaves that marker
unassessed in version `3` and in custom role names. Conditional bindings cannot
erase known unconditional witnesses, but relevant unresolved conditions keep
the overall query inconclusive.

Every ancestor requires an explicit supplied policy, including an explicitly
empty policy. A global completeness claim cannot fill a missing ancestor policy.
Missing resources, dangling policy resources, incomplete ancestry or policy
coverage, relevant unavailable group membership and unassessed deny/PAB coverage
remain uncertainty. Contradictory parent kinds, cycles, duplicate identities or
ambiguous bindings reject rather than select a winner.

Results are `matching_supplied_allow_binding`,
`no_matching_supplied_allow_binding` or `inconclusive`. Known witnesses survive
beside sorted uncertainty reasons. A no-match is not effective GCP
denial. A witness is not permission to operate. Supplied completeness, principal
identity, membership, role contents, policy applicability and timestamps have no
authenticated provider provenance. Organization constraints, service-specific
restrictions, access policies, propagation and actual effective access remain
unverified even when no uncertainty was declared in this subset.

## Bounds and source replay

Limits are 4 MiB conservative JSON accounting, 100,000 native node occurrences,
depth 24, 4,096-character printable ASCII values, 512 resources, ancestry 32,
128 roles, 512 policies, 1,024 total bindings, 8,192 total permission entries,
4,096 total member appearances, 128 groups per query, 128 queries, 2,000,000
charged matching units and 2,048 total witnesses. Aggregate byte and node limits
can reject combinations below individual limits. They are software bounds, not
Google IAM quota coverage or a runtime performance qualification.

Native input is owned and budgeted before source serialization or hashing.
Repeated shared subtrees are charged separately; cycles, subclasses, floats,
boolean/integer substitutions, unknown fields and non-ASCII/control text reject.
Every primitive charge, including the final value, checks the byte budget.
Witness count is checked before append and full output is bounded before its
report-domain hash. The byte interface checks physical bytes, node/value counts,
nesting, quoted-value lengths and escaped-output charges before JSON decoding,
then repeats native capture. Duplicate keys
at every level, nonfinite values and oversized integers reject. Signed64 limits
are checked during raw preflight and in the decoder's integer callback itself.

Source arrays preserve their supplied order and bind canonical parsed JSON.
Results and witness presentation use deterministic ordering. Whitespace changes
can produce the same canonical parsed sources; this is not a hash of original
wire bytes. A content hash is unsigned metadata, not evidence authenticity.
Embedded replay rejects cohashed false results, omissions, effects and aliases.
It cannot prove which sources a caller originally possessed. The separate-input
verifier binds the supplied original snapshot and queries and rejects another
valid model substituted into the report. Exports validate the current report
text and embedded replay, not authenticated construction history or a valid
whole-record substitution. No arbitrary Python sandbox or concurrent-memory
guarantee is made.

## Local checks and primary semantics

Run `python -B -m unittest tests.agents.test_gcp_iam_analysis` with `PYTHONPATH=src`.
The tests use native synthetic declarations and no signing or provider calls.
Passing these tests does not qualify a specialist, authorize routing or select
deployment resources.

Semantics follow Google's [allow-policy documentation](https://docs.cloud.google.com/iam/docs/allow-policies),
[resource hierarchy](https://docs.cloud.google.com/iam/docs/resource-hierarchy-access-control),
[role overview](https://docs.cloud.google.com/iam/docs/roles-overview),
[Role REST schema](https://docs.cloud.google.com/iam/docs/reference/rest/v1/organizations.roles),
[principal identifiers](https://docs.cloud.google.com/iam/docs/principal-identifiers)
and [policy types](https://docs.cloud.google.com/iam/docs/policy-types), checked
on 28 September 2026. Unsupported facts remain unresolved rather than guessed.
