# GCP service boundaries: offline declaration review

This module implements a bounded part of row 2 in the
GCP planning backlog. It reviews explicit
service-to-account assignments and application-network declarations for the
declared `us-west3` planning region. It does not emit IAM policies,
firewall rules, deployment templates, credentials, signed authority, or runtime
admission. Every result is `valid_for_offline_planning_only`, operator-asserted,
unsigned, and nonqualifying. No transport, cloud SDK, file mutation, DNS lookup,
key access, provider request, or target action is implemented.

## Explicit inputs and existing sources

`review_gcp_service_boundaries(inputs, *, resource_plan, dossier,
deployment_profile, regional_binding, egress_policies)` returns an immutable
`GcpServiceBoundaryReview`. All sources must be explicitly supplied. The
resource plan is replayed through `verify_gcp_resource_binding_plan` against
the exact existing D014 dossier, deployment profile, and tenant region binding.
Each supplied `EgressPolicy` is reconstructed and compared using canonical,
type-sensitive JSON before use. There is no trust acquisition or discovery.

The closed input object contains four fields:

- `service_assignments`: a bounded array of `service_ref`, `role`,
  `service_identity_ref`, and `operations`. Each operation contains an exact
  `operation` and `resource_ref`.
- `application_network_edges`: explicit `worker_service_ref`, `worker_ref`,
  `proxy_service_ref`, `policy_id`, `policy_sha256`, `resolver_ref`, and
  `proxy_only: true`.
- `host_resolver_policy`: null, or a DNS-only declaration with `resolver_ref`,
  `proxy_service_ref`, canonical IP `addresses`, exact integer `port: 53`,
  explicit `tcp` and/or `udp` transports, and `worker_direct_dns: false`.
- `stop_binding`: null, or the exact existing deployment profile's complete
  stop, cleanup, restoration, and acknowledgement-bound declaration.

Service roles reuse the existing deployment manifest vocabulary. Non-custody
roles have no custody operations in this matrix. Supported custody roles reuse
six D012 provider interface IDs: retention-locked ledger objects, conditional
ledger head, immutable catalog objects, release-head signing, release-head
verification, and release audit. Their allowlists are copied from the existing
D012 interface descriptors. These are contract-port names, not Google IAM
permissions or an assertion that a GCP adapter implements every port.

Storage operations must bind declared bucket references. Signing and signature
verification operations must bind declared asymmetric-signing key references,
not an encryption key or an arbitrary opaque reference. Wildcard, administrative,
unknown, and role-inappropriate operations are rejected. Account references
must resolve to the resource plan's explicit service-account unique IDs.
Workers cannot alias custody or other trusted services. Proxies cannot alias
custody. Release signing and verification identities must remain independent.
These declarations do not inspect effective, inherited, or federated IAM.

Each application edge joins a declared worker, a declared egress proxy, and the
exact supplied policy identity and digest. Worker and tenant references must
match the deployment profile and region binding. Mission and scope references
remain part of the policy's content address, not proof of mission authorization.
Every supplied policy must be used by an explicit edge. Disconnected deployment
profiles cannot acquire application-network edges through this reviewer.

## Worker metadata denial and host DNS

Worker application rules cannot permit `metadata.google.internal`,
`metadata.goog`, the short `metadata` alias, IPv4 `169.254.169.254`, or IPv6
`fd20:ce::254`. CIDR overlap is checked rather than equality: broad ranges and
IPv4-mapped IPv6 ranges containing the known IPv4 endpoint are rejected.
The existing egress parser also rejects noncanonical case, trailing dots,
single-label hosts, and IP literals. None can become an accepted bypass here.

Google documents the IPv6 metadata endpoint for IPv6-only VMs. It also
documents host DNS at `169.254.169.254`. Therefore the separate host resolver
declaration may name these addresses for DNS port 53. That does not permit
worker direct DNS or HTTP/HTTPS metadata access. An edge's resolver and proxy
must match the supplied host resolver declaration exactly.

This is protection of platform workers and host credentials. It is not a
finding about a remote target or permission to test a target's SSRF behavior.
No metadata request, token request, or DNS query occurs. Current endpoint and
DNS facts were checked on 2026-09-27 using Google's primary documentation:
[metadata overview](https://docs.cloud.google.com/compute/docs/metadata/overview)
and [metadata/DNS troubleshooting](https://docs.cloud.google.com/compute/docs/troubleshooting/troubleshoot-metadata-server).

## Partial inputs and permanent blockers

Null resolver or stop inputs remain explicit owner-input blockers. Missing
worker, proxy or custody assignments, a worker without a declared edge, and a
custody role without a scoped operation also remain blockers. No account,
resolver, destination, operation, policy, or stop value is generated as a
default. Structurally valid partial declarations can be inspected, but cannot
become ready or authorized.

Every review retains the resource plan's exact blockers, including the
unselected recovery region and any missing coordinates or managed PostgreSQL
manifest mapping. Permanent review blockers also retain authenticated D014
selection, effective IAM and federation policy, object namespace and effective
scope policy, actual network and DNS enforcement, worker containment, incident
ownership and stop enforcement, provider configuration, and independent
production go or no-go evidence. This module cannot clear those blockers.
The Cloud SQL mapping blocker belongs to the version 1 alternative-design
resource plan. The self-managed PostgreSQL design has
its own static manifest crosswalk
and still lacks exact hosts, database failover and fencing proof, and signed
runtime observations. This service review cannot convert Cloud SQL coordinates
into self-managed acceptance evidence.

Exact owners must still supply the organization/folder/project hierarchy and
inherited administration; intended service identities and resource scopes;
network routes, DNS, proxies, enforcement and emergency-stop configuration;
host and service acceptance evidence; incident responders; and complete D014
choices. Actual least privilege and containment require external conformance.

## Integrity, bounds and replay

Inputs and wire records use exact native dictionaries, lists, strings,
integers, booleans, and nulls. Floats, subclasses, unknown fields, duplicate
JSON keys, non-ASCII/control text, and ambiguous declarations are rejected.
Arrays are limited to 128 items, declaration depth to 12, and the complete
canonical review to 256 KiB. Existing resource-plan source validation retains
its own source-contract collection limits. Egress sources are an exact native
tuple of at most 128 exact typed policies.

The 256 KiB aggregate encoded-byte budget is enforced while visiting native
values, before JSON allocation and before an oversized string is scanned.
Accounting includes structural punctuation, quoted keys, and printable quote
and backslash escapes. Repeated containers are charged on every occurrence,
so shared Python graphs cannot cause unbounded expanded traversal. The visitor
budget is 262144 nodes, including object keys, a bound already implied by the
byte limit for valid JSON. Cycles fail at the depth bound. Huge native integers
are rejected by a lower decimal-size bound before conversion; the byte limit
and Python's existing encoding guard remain applicable without a new source
integer-family ceiling. Canonical bytes and source-array limits are unchanged.

Assignments, operation scopes, edges, resolver addresses/transports, and policy
source bindings are canonicalized in deterministic sorted order. The digest
domain is `sunderkey.gcp-service-boundary-review.v1`. A frozen record stores
owned canonical JSON; each export is detached. `from_dict` and `from_json`
check the closed wire contract and content identity, not source authenticity.

`verify_gcp_service_boundary_review` rebuilds the review from all explicitly
supplied sources and compares canonical bytes. Rehashed source substitution,
removed resource-plan blockers, stale account recreation bindings, late source
mutation, and metadata/effect escalation do not pass replay. The verifier
returns a new owned record. Neither parsing nor successful replay is a
positive runtime-use or qualification gate.

All effects remain `none`, including authorization, credential access,
deployment, IAM mutation, network, qualification, signature generation,
storage mutation, and target action. The synthetic tests use documentation
addresses, public metadata coordinates, and inert account/key names. They do
not contact any of them or generate keys.

Focused software check:

```powershell
$env:PYTHONPATH = 'src'
python -B -m unittest tests.agents.test_gcp_service_boundaries -v
```

This software result supplies no live IAM, DNS, routing, isolation, stop,
retention, deployment, or signed production acceptance evidence.
