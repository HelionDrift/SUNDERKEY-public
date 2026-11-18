# Supplied Azure RBAC permission analysis

`sunderkey.azure_rbac_analysis` implements a finite, pure permission evaluator
over supplied inert models. It uses no Azure client, SDK, network, process,
credential, provider catalog, live clock or callback. It does not issue an
access decision for Azure or authenticate source facts.

## Existing lane and unchanged gates

The partial component belongs to `AOE-GC-D14-S04`, capability
`army.gc.d14.s04`, vector `AV-GC-D14-S04-01`, package
`IWP2-AOE-GC-D14-S04` and existing wave `IW2-007`. Its domain commander is
`AOE-GC-D14-CMD`, group commander `AOE-HQ-05` and independent validator
`AOE-HQ-19`. The technical staging strategy permits inert
implementation and synthetic tests. This component does not assemble the
ten-component specialist package, replace the six reference SDKs or satisfy
real-host containment, qualification, routing or live-use gates.

## Closed supplied model

`analyze_azure_rbac(snapshot, queries)` accepts exact native JSON objects and
lists. The input is a deliberately small projection, not arbitrary Azure REST
responses. A producer must explicitly preserve unsupported condition and
eligibility facts rather than discard them. No projection authenticity is
established by this library.

The snapshot has exactly these fields:

```json
{
  "schema_version": 1,
  "tenant_id": "tenant:synthetic",
  "scopes": [
    {"scope_id": "/subscriptions/sub-one", "kind": "subscription", "parent_scope_id": null}
  ],
  "role_definitions": [
    {
      "role_definition_id": "role:reader",
      "role_type": "custom",
      "assignable_scopes": ["/subscriptions/sub-one"],
      "permissions": [
        {
          "actions": ["Microsoft.Storage/*/read"],
          "not_actions": [],
          "data_actions": [],
          "not_data_actions": [],
          "condition": null,
          "condition_version": null
        }
      ]
    }
  ],
  "role_assignments": [
    {
      "assignment_id": "assignment:reader",
      "tenant_id": "tenant:synthetic",
      "principal_id": "principal:alice",
      "role_definition_id": "role:reader",
      "scope_id": "/subscriptions/sub-one",
      "state": "active",
      "condition": null,
      "condition_version": null
    }
  ],
  "coverage": {
    "role_assignments_complete": true,
    "scope_ancestry_complete": true,
    "deny_assignments": "none_supplied"
  }
}
```

Each query has exactly:

```json
{
  "query_id": "read-account",
  "tenant_id": "tenant:synthetic",
  "principal_id": "principal:alice",
  "group_ids": [],
  "group_membership_complete": true,
  "scope_id": "/subscriptions/sub-one",
  "operation": "Microsoft.Storage/storageAccounts/read",
  "plane": "control"
}
```

Queries must specify literal action names with no wildcards. Their existence
and their declared `control` or `data` plane are not independently verified.
`group_ids` declares all supplied direct or transitive groups; no directory or
membership expansion is performed. Tenant, principal and reference identifiers
are bounded ASCII references, not authenticated Entra subjects.

Scope kinds are `management_group`, `subscription`, `resource_group` and
`resource`. The supported ASCII ARM paths include subscription resource groups,
nested resource type/name pairs and extension-resource provider segments.
Malformed paths and contradictory parent edges are rejected. Management-group
parents and subscription-to-management-group edges must be supplied explicitly;
they are never inferred from lexical prefixes. A null subscription or
management-group parent terminates the supplied tree, not the real Azure tree.
Missing parents for resource groups or resources, dangling scopes and unknown
query scopes remain uncertainty. Case-insensitive joins retain the original
source text in the addressed snapshot and witnesses. Unicode names and other
ARM path forms are outside this finite input subset.

## Implemented semantics

For each applicable permission block, control matching evaluates `Actions`
minus `NotActions`; data matching evaluates `DataActions` minus
`NotDataActions`. Applicable roles add grants. An exclusion is not a global
deny: another applicable role can regrant the excluded operation.
Control wildcards do not create data-plane permissions. The algorithm only
tests finite explicit queries; it does not enumerate Azure operations or
predict future wildcard expansion. [Microsoft role definitions](https://learn.microsoft.com/en-us/azure/role-based-access-control/role-definitions)

The first subset supports a single permission block per role. A role with
multiple blocks is retained in source replay but explicitly inconclusive,
without grant witnesses from that role. This does not assume that a block can
regrant another block's exclusion within the same role; the documented
separate-role regrant rule is supported.

Permission strings are compared case-insensitively. The implemented selector
subset uses at most one documented `*` wildcard per pattern, matching the
complete operation string. Patterns are `*` or bounded ASCII action text
containing a slash; literal queries contain a provider and at least two
additional slash-separated segments. `?`, variables and other selectors remain
unsupported, not clean negative permissions. [Microsoft custom-role permissions](https://learn.microsoft.com/en-us/azure/role-based-access-control/custom-roles)

An assignment must join the supplied tenant, principal or declared group, role
definition and an ancestor of the query scope. Scope inheritance uses explicit
parent edges, so sibling subscriptions, resource groups and similarly prefixed
scope names do not inherit each other's grants. `AssignableScopes` controls
role availability, not permission creation. A custom role with root availability,
multiple management-group availability or data permissions assigned directly
at a management group is outside the supported configuration and remains
inconclusive. Built-in root availability and custom data roles assigned to a
subscription below a declared management group remain supported.
[Microsoft scope inheritance](https://learn.microsoft.com/en-us/azure/role-based-access-control/scope-overview)

Assignment `state` is `active`, `eligible` or `unknown`. Only declared active,
unconditioned assignments can provide known witnesses. Non-null role or
assignment `condition` or `condition_version`, eligibility, unavailable source
coverage and declared present or unknown deny assignments remain explicit
uncertainty. No ABAC expression, PIM activation or deny rule is evaluated.
`none_supplied` is only a declaration, never proof of absence in Azure.
[Microsoft authorization overview](https://learn.microsoft.com/en-us/azure/role-based-access-control/overview)

Any unsupported supplied source produces a sorted `source_issues` entry and
makes every query inconclusive. This intentional conservative policy also
applies to unresolved sources that could later prove irrelevant. Separately
known unconditioned grant witnesses remain visible beside uncertainty. An
unsupported exclusion or conditioned block never supplies a known witness.
Duplicate case-insensitive source identities, duplicate permission blocks,
duplicate selectors, contradictory scope kinds or parents and ancestry cycles
are rejected rather than arbitrarily selecting one declaration.

## Results, exact replay and bounded cost

Outcomes are `matching_supplied_role_grant`,
`no_matching_supplied_role_grant` or `inconclusive`. Neither a match nor no
match is effective access, actual denial, IAM safety or a live finding.
Witnesses bind the selected assignment, principal match, exact permission-block
digest, scope path and matching patterns. Results and reasons are sorted.
Reordering source arrays preserves semantic results when their member records
are unchanged, but changes their source addresses. Source order is not silently
normalized away.

`AzureRbacAnalysis` is a frozen, detached canonical document with `to_dict`,
`to_json`, `from_dict` and `from_json`. Parsing and export re-run the algorithm
over the complete embedded snapshot and queries. Report domain is
`sunderkey.azure-rbac-analysis.v1`; source, query and permission addresses use
separate domains. A coherently readdressed false outcome or witness cannot
substitute for derived output. A separately valid changed model remains
unsigned supplied data: `verify_azure_rbac_analysis(analysis, snapshot=...,
queries=...)` additionally requires the independent original sources.

`analyze_azure_rbac_bytes(snapshot_bytes=..., queries_bytes=...)` and report
`from_json` accept bounded native UTF-8 bytes and reject duplicate object keys
at every depth. Digests bind canonical parsed JSON, not original whitespace or
raw-file provenance. No file is read or written by any public function.

Fixed bounds are 4 MiB JSON bytes, 100,000 visited nodes, depth 24, 512 scopes,
scope ancestry depth 32, 128 roles, 512 assignments, 512 permission blocks,
2048 permission patterns, 128 queries, 2,000,000 matching-work units and 2048
aggregate witnesses. Local arrays are at most 128 entries; a role has at most
16 permission blocks. Text is printable native ASCII, at most 4096 characters
globally and 512 for ordinary fields; condition text is at most 2048.

Native intake checks types, cycles, repeated shared containers, integer size
and a conservative serialized-byte budget before dumps, hashing or matching.
JSON integer token length is bounded before conversion, and converted native
integers must fit signed64 before further processing;
booleans cannot substitute for integer schema fields and integers cannot
substitute for booleans. Floats, nonfinite values and subclasses are rejected.
Matching work is charged before each bounded string match; witness count and
aggregate byte budgets are charged before witness expansion. Output budget
checks occur before complete-report serialization and addressing. Combined
budgets may reject an otherwise individually bounded collection; limits are
cost ceilings, not guaranteed Cartesian capacities or provider throughput.

Every report retains `offline_only=true`, `effective_access_verified=false`,
`qualification_claimed=false` and fixed `none` effects for authority,
qualification, routing, execution, deployment, provider and target interaction.
No signed receipt, credential, grant, target request or deployment is produced.
Software replay does not authenticate source capture, current state, tenant
ownership, membership, role activation, observation time or independent review.

Tests use inert native role and scope fixtures only. They do not select an Azure
tenant, contact a provider, create credentials or promote a specialist package.
