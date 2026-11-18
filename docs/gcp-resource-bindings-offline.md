# GCP Resource Bindings: Offline Validation

## Implemented boundary

`sunderkey.gcp_resource_bindings` validates declared GCP coordinates for the
declared `us-west3` planning region. It provides one immutable,
content-addressed `GcpResourceBindingPlan`, a strict parser, a builder, and an
exact supplied-source verifier. The schema is
[`gcp-resource-binding-plan-v1.schema.json`](../registry/schemas/gcp-resource-binding-plan-v1.schema.json).

This is a coordinate-validation slice, not a deployed cloud adapter or a
completed D014 selection. Every effect remains `none`, the identity assurance
is `operator_asserted_unsigned`, and the validation scope is
`declared_coordinates_only`. Successful checking means only
`valid_for_offline_planning_only`; it never means ready, qualified, or authorized.

The layer is separate from existing deployment posture, tenant regional
custody, retention, containment, and authenticated authority contracts. It
does not create organizations, projects, accounts, resources, keys, signatures,
credentials, policies, or provider observations. It has no SDK, default
transport, credential discovery, network client, or provisioning operation.

## Explicit inputs and exact sources

All coordinate inputs are required fields, even when a collection is empty:

| Input | Required declaration |
| --- | --- |
| `provider` | Exactly `gcp` |
| `primary_region` | Exactly `us-west3` |
| `recovery_region` | Exactly null in version 1; no recovery location is selected |
| `projects` | One or more native project-ID and decimal-string project-number pairs |
| `service_accounts` | Logical principal reference, declared project, user-managed account ID, and decimal-string unique ID |
| `kms_key_versions` | Logical key reference, exact version resource, purpose, algorithm, and protection level |
| `gcs_buckets` | Logical storage reference, declared project, supported bucket name, region, and declared encryption-key reference |
| `cloud_sql_instances` | Logical component reference, declared project, instance ID, region, explicit primary zone, and nullable secondary zone |

The builder takes the actual `ProductionDeploymentDecisionDossier`,
`DeploymentProfile`, and `TenantRegionBinding` objects. It reconstructs their
strict records before binding the exact identities and digests. The verifier
requires those same supplied source records; self-consistent hashes alone do
not count as source verification. Neither revalidation nor a content address
authenticates an owner, proves current provider configuration, or proves source
origin. Runtime use still needs its original live-currentness checks.

The tenant home region and its storage and processing allowlists must contain
the primary region. No transfer is authorized by an allowlist, and this plan
does not consume transfer approval. Missing coordinates for the profile's
evidence store or tenant encryption key remain visible blockers rather than
inferred defaults. Declared buckets must reference the tenant's encryption key.

## Native-coordinate support and limitations

Project IDs use the documented lexical shape; project numbers remain strings.
Known restricted name forms are rejected, but this check does not determine
whether a project exists, has ever been used, or has correct ownership,
organization, folder, billing, quota, or inherited IAM. See
[project identifiers](https://docs.cloud.google.com/resource-manager/docs/creating-managing-projects).

Only user-managed service accounts with explicit unique IDs are supported.
Redundant caller-supplied email fields are not accepted. The declared project
and account ID determine the email, while the unique ID pins the identity;
recreation changes the plan identity even if the email is reused. These are
claims, not authenticated account observations. See
[service-account lifecycle](https://docs.cloud.google.com/iam/docs/service-account-overview).

KMS coordinates must end in a positive decimal `cryptoKeyVersions` value in
`us-west3`. Moving aliases, bare keys, encoded path segments, traversal,
undeclared projects, and location substitution are rejected. The supported
profiles are symmetric encryption using `GOOGLE_SYMMETRIC_ENCRYPTION` with
SOFTWARE or HSM protection, and `EC_SIGN_ED25519` signing with SOFTWARE
protection. Versions of a single CryptoKey cannot contradict its immutable
purpose or protection profile. Separate purposes remain separate key domains.
See [KMS algorithms](https://docs.cloud.google.com/kms/docs/algorithms) and
[CryptoKey metadata](https://docs.cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys).

Pinned application envelope-key versions are not Cloud Storage's default CMEK
CryptoKey setting. Version pinning does not establish version-scoped IAM:
Google's key access policy remains a separate integration requirement. No
provider key availability, enabled state, authorization, or protection evidence
is inferred from these strings.

Bucket support deliberately uses a conservative 3-to-63-character lowercase
letter, digit, and hyphen subset. Dotted and underscored names may be valid in
GCP but are outside this version's supported profile. Known reserved forms
are rejected. Bucket names are globally scoped; the supplied project claim
does not prove bucket ownership. No `US`, global, dual-region, or zone location
is substituted for `us-west3`. See
[bucket naming](https://docs.cloud.google.com/storage/docs/buckets) and
[storage locations](https://docs.cloud.google.com/storage/docs/locations).

Cloud SQL IDs retain the combined `project-ID:instance-ID` length bound.
Declared zones are explicit members of `us-west3-a`, `us-west3-b`, and
`us-west3-c`; a secondary zone, when supplied, must differ. None proves HA,
replication, failover, service support, or capacity. In particular, the current
three-node self-managed PostgreSQL manifest is not automatically compatible
with managed Cloud SQL HA. The result always retains
`managed_sql_manifest_mapping_required` when SQL coordinates are present.
See [Cloud SQL instance settings](https://docs.cloud.google.com/sql/docs/postgres/instance-settings).

The owner later chose to retain self-managed PostgreSQL for D014. This version
1 Cloud SQL coordinate field remains an alternative-design planning contract,
not the current database resource plan. An empty `cloud_sql_instances` list
does not map or validate self-managed database hosts. Use the
static self-managed crosswalk for
the current choice; exact hosts, zones, replication, fencing, and recovery
still require separate owner inputs and external proof.

Cross-resource uniqueness, project declaration, tenant-key linkage, exact
source identity, and content digests are runtime-validator checks in addition
to JSON Schema's structural checks.

## Validate-only command

Supply explicit local files; there is no credential or source autodiscovery:

```sh
python scripts/check_gcp_resource_bindings.py --input supplied-gcp-coordinates.json --dossier registry/production-deployment-decision-dossier-d014.json --deployment-profile supplied-deployment-profile.json --regional-binding supplied-tenant-region-binding.json
```

Use `PYTHONPATH=src` with the shell-appropriate syntax from the README.
The command bounds reads to regular UTF-8 files, rejects duplicate keys and
nonfinite or unsupported primitives, and emits only a planning summary to
standard output. It never modifies source files or writes a plan, deployment
configuration, credential, or provider receipt. Failure returns exit code 2
without echoing untrusted values or raw exception text.

Coordinate collections are bounded to 128 rows. Supplied source records retain
their own contract collection limits, rather than inheriting that coordinate
limit. Source metadata is checked for native integer version 1 before the
existing source parsers are invoked; boolean and floating-point aliases fail.

Native canonicalization enforces the 256 KiB aggregate encoded-byte budget
during traversal, before JSON allocation and before oversized string scans.
Accounting includes braces, brackets, commas, colons, quoted keys, and escaping
of printable quotes and backslashes. Every occurrence of a shared container is
charged, so a small Python graph cannot expand indefinitely before rejection.
The aggregate visitor budget is 262144 nodes, including object keys; this adds
no restriction to a document within the byte limit because each JSON node
requires at least one encoded byte. Cycles fail at the existing depth bound.
Native integers are checked with a lower decimal-size bound before conversion;
the existing byte limit and Python's existing integer-encoding guard apply,
not a new integer-family or source-array ceiling. Valid canonical bytes and
source contracts' own collection limits remain unchanged.

Pure synthetic inputs are exercised in
[`test_gcp_resource_bindings.py`](../tests/agents/test_gcp_resource_bindings.py).
They select no actual project, account, bucket, database, key, or tenant.

## External and decision gates remain

Every result retains authenticated D014 selection, unknown provider
configuration, unbound organization/folder/billing, unselected recovery region,
unverified worker containment, and a separate production go or no-go decision.
Partial inventories additionally report missing service, storage, encryption,
and database coordinates. No zero-blocker production result exists in version 1.

No grant, permission, key use, database migration, storage retention lock,
transport mutation, worker invocation, live qualification, or target operation
is unlocked by this module. Follow the
GCP planning brief and the ordered
infrastructure handoff for the remaining gates.
