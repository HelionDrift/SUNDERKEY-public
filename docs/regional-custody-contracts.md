# Regional custody contracts

This increment adds repository-only contracts for roadmap packages S6.7 and
S6.9. It defines tenant isolation, regional custody, retention, holds, and
operation admission without claiming that any supporting infrastructure is
deployed.

## Contract records

`TenantRegionBinding` pins one tenant to an exact policy digest and version,
home region, allowed storage and processing regions, and an opaque tenant key
reference. Key references are identifiers only. Raw key material is rejected.

`ArtifactCustodyDescriptor` binds an artifact digest to its evidence digest,
scope digest, policy digest and version, retention schedule version, data
classification, current regions, and tenant key reference.

`CrossRegionTransferRequest` describes a planned transfer. It requires a legal
basis reference and exactly two approvals from distinct principals holding the
independent Control and independent Assurance roles. The record always states
`planned_only`. It cannot claim a completed transfer.

`RetentionSchedule` carries a policy-defined minimum and an effective
retention duration. A schedule shorter than its required minimum is rejected.

`CustodyHold` models litigation, incident, or regulatory holds. Active holds
cannot have release times. Released holds require a later release time.

`DeletionEligibilityPlan` records whether the retention interval and grace
period have expired and whether an active hold remains. An eligible result is
only a plan for an external execution system. It does not delete data.

`OperationAdmissionDecision` evaluates storage, processing, transfer, and
deletion bindings. A successful result means only that the contract is
eligible for a separate authorization decision. The result has no authority.

## Fail-closed rules

The evaluator denies an operation when any exact tenant, artifact, evidence,
scope, policy, version, key, region, transfer, retention, or hold binding is
missing or inconsistent. Unknown regions are denied. Cross-tenant reuse is
denied. Cross-region transfers require the bound request, legal basis, and
independent approvals. Deletion requires an eligible bound plan and is denied
while a hold is active or retention remains in force.

Every top-level record is content addressed and uses canonical JSON. Parsing
rejects unknown fields, changed content addresses, noncanonical JSON, effect
escalation, raw secrets, and execution claims.

## Deliberate boundaries

This module does not:

- persist tenant or artifact data
- connect to a database, cloud, key manager, or policy service
- access or resolve encryption key material
- move, replicate, store, process, or delete an artifact
- create legal authority or approve an operation
- execute a retention job or release a hold
- qualify a deployment or prove runtime tenant isolation

Runtime completion still requires isolated production storage, regional
deployment controls, key manager integration, independently administered
approval identities, audited transfer services, durable hold enforcement,
deletion workers, and observed conformance evidence.

## Schema

`registry/schemas/regional-custody-contract-v1.schema.json` validates every
top-level record with closed fields and closed effect values. Application code
must still use the Python parser to verify content addresses and semantic
cross-record constraints.
