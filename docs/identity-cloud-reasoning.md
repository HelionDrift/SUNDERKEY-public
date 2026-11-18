# Identity and Cross-Surface Reasoning

The Phase 166 identity reasoning layer implements the repository-only portions of roadmap packages C4.1, C4.2, C4.9, and C4.10. It builds a provider-neutral view of identity, permission, credential, workload, cloud, and data relationships from caller-supplied evidence. It then resolves effective permissions and searches for complete paths from application, container, or workload identities to cloud and data resources.

## Safety boundary

`sunderkey.identity_cloud_reasoning` is an offline reasoning contract. It does not contact identity or cloud providers, use credentials, mutate policies, authorize activity, interact with targets, or execute exploits. Every serialized snapshot and validation plan declares these effects as `none`:

- authorization
- credential use
- network activity
- policy mutation
- provider calls
- target actions

Credential objects are references and digests only. Secret-like identifiers are rejected. A reasoning result describes the supplied evidence, not current provider state and not authority to act.

## Content-addressed graph

The snapshot contains immutable, content-addressed records for:

- principals, groups, roles, and policies;
- cloud and data resources;
- credential references and workload identities;
- trust relations and session or credential transitions;
- allow and deny permission facts;
- evidence bindings with observed and expiry times.

Every record carries a tenant and assessment context. A snapshot fails closed when a record crosses either boundary, references an unknown object, exceeds the 512-record budget, contains a malformed digest, or is changed without recomputing its content address. Deserialization rejects extra fields and modified effect declarations.

## Effective permissions

Resolution starts from one subject, resource, action, bounded attribute map, and evaluation time. It expands workload bindings, group membership, and conditional trust relations. The only supported condition keys are audience, environment, network zone, region, resource class, session assurance, tenant, and workload namespace. Operators are equality, set membership, and presence.

The resolver returns exact allow, deny, unknown, cycle, and provenance identifiers. It expands only identity and group records with current evidence. A stale or unknown starting subject, target resource, workload binding, group membership, or trust target keeps a positive conclusion indeterminate. A permission fact is operative only when a policy attaches it to its subject and that policy has current evidence. Unattached facts cannot grant or deny access; a matching fact attached only through stale or unknown policy evidence remains indeterminate. Current policy IDs are included in provenance. Explicit deny takes precedence over allow. A matching allow and deny is both denied and recorded as a conflict. Missing condition inputs, stale or unknown evidence, graph cycles, and an exhausted depth budget produce an indeterminate result instead of an optimistic result.

## Credential transitions

Role assumption, federation, and token exchange transitions require a credential reference. A workload binding transition must not carry one. The credential owner must be the transition source. Path search checks both the transition evidence and credential evidence and rejects expired credentials as indeterminate. The module never retrieves or uses the referenced credential.

## Cross-surface path search

Path search begins at a content-addressed application, container, or workload identity and ends at a cloud or data resource. It traverses workload bindings, trust relations, and declared session transitions in deterministic order. A path is complete only when a traversed subject has a direct effective allow to the requested resource and action.

Callers must select budgets no larger than 16 edges and 64 returned paths. Repeated nodes are recorded as cycles, exhausted budgets are marked as truncated, and stale, unknown, or conditionally unresolved edges are preserved as indeterminate references. A result cannot be labeled complete while any retained path evidence is indeterminate or the result is truncated.

## Conflict detection and independent validation

Conflict reports identify exact-record allow and deny contradictions, trust or session graph cycles, unknown evidence, and stale evidence. Reports are deterministic and content addressed.

A complete-path validation plan can be built only from a complete, non-truncated search result with at least one path. The builder requires the original evaluation attributes and `as_of` time. It replays the bounded search against the supplied snapshot and rejects a content-addressed result that differs from that replay, including a fabricated edge, stale evidence, or a changed condition. Evidence observed after `as_of` cannot establish a path, and plan creation rejects an evaluation time before the snapshot observation. The plan binds the attribute digest and evaluation time; a later user must call `verify_complete_path_validation_plan` with the snapshot, result, plan, and original context to replay them again. This verifies historical consistency only, not present-time provider state.

The separate [offline hop plan](identity-path-hop-plan.md) expands a replayed reviewed path into exact workload, trust or session, and terminal permission evidence obligations. It remains a non-authorizing checklist.

Two different reviewers are required: one independent identity reviewer and one independent assurance reviewer. Each accepted review must bind the exact path-set digest and an evaluation-context digest over `snapshot_sha256`, `search_result_sha256`, `attributes_sha256`, and `evaluated_at`. Reusing a review for the same path IDs under a different context fails. Reviewer IDs and evidence digests remain caller assertions, not authenticated identities or independent review proof. The output is still an inert plan with no provider, credential, policy, network, authorization, or target effects.

## Remaining infrastructure work

Live provider adapters, authenticated inventory, credential brokerage, policy evaluation against provider engines, continuous drift collection, runtime path validation, and operational authorization remain external infrastructure. Those systems must preserve tenant isolation, stop controls, evidence custody, audit logging, and separate authorization before any target interaction.

## Verification

`registry/schemas/identity-cloud-reasoning-v1.schema.json` validates the serialized snapshot shape independently of the Python loader. Focused tests cover deterministic content addresses, strict round trips, schema validation, policy attachment and identity-record freshness, deny precedence, provenance, conflicts, bounded conditions, stale and unknown evidence, credential policy, credential expiry, cycles, tenant isolation, path budgets, complete-path review separation, forged path rejection, context-bound plan replay, effect tampering, secret rejection, and immutable input copying.
