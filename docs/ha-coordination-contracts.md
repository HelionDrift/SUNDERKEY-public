# High-availability coordination contracts

This increment adds repository-only contracts for roadmap package S6.5. It
defines the evidence and fail-closed decisions needed around leader coordination,
quorum, fencing, failover, degraded operation, and recovery. It does not claim
that a consensus system or highly available runtime is deployed.

## Contract records

`ClusterMemberDeclaration` binds a member to an exact tenant, service, cluster,
service version, cluster version, role, state, region, and declaration version.
Only an active voter may be declared eligible for leadership.

`LeaderEpoch` binds one eligible member to a monotonic epoch, exact prior epoch,
caller-supplied issuance time, lease expiry, and maximum clock skew. The record
does not elect or activate the member.

`QuorumObservationSet` records observations from distinct configured voters.
It requires a strict majority threshold, caller-supplied observation times
within the declared skew window, and unexpired observed leases. Observations
may disagree because disagreement is evidence that must be assessed, not
silently discarded.

`SplitBrainAssessment` reconciles one or more observation sets. A `clear`
result requires quorum support for the exact expected leader and epoch, a live
leader lease, and no observer conflict. Ambiguous reports, an unexpected quorum
leader, multiple quorum leaders, insufficient quorum, and stale epochs produce
blockers.

`FencingGrant` describes a deterministic fence that is only eligible for an
external atomic commit. It binds the exact leader epoch, observation set,
resource, resource version, member, and expiry. A prior grant can be supplied
to reject epochs or resource versions that move backward. The record does not
persist or enforce the fence.

`FailoverPlan` describes a successor, the exact next epoch, fenced resource,
and expected resource version. It always states `planned_only`.
`FailoverObservation` binds the plan to the exact successor declaration,
observed new epoch, resource fence, and required recovery evidence. Even a
complete observation remains unqualified.

`RecoveryEvidenceRequirements` defines the evidence set and independent
observer threshold for recovery. Quorum, epoch, fence, durable state, outbox,
and scheduler continuity are mandatory. Mission stop and execution session
reconciliation can also be made mandatory by the selected requirements record.

`DegradedServiceMode` has a closed operation matrix. Read-only and stop-only
modes permit no writes through this contract. Control-plane-only mode permits
only a control-plane write. Target action dispatch is never admitted by a
degraded mode.

`SafeWriteAdmission` is a no-authority eligibility record. It requires matching
tenant, service, cluster, and version bindings across the leader epoch, quorum
observations, split-brain assessment, fencing grant, and optional degraded
mode. The evaluator denies on ambiguity, insufficient quorum, an expired lease,
a stale or mismatched fence, a resource-version mismatch, or a degraded-mode
restriction. An eligible result still requires all separate SUNDERKEY scope,
mission-stop, execution-session, credential, action-tier, approval, and target
authorization gates.

## Integration boundaries

These contracts align with existing repository boundaries:

- persistence transaction batches must atomically check expected aggregate
  versions and fence bindings
- durable scheduler leases use monotonic fence epochs and reject stale claims
- integration outbox claims use fencing tokens and reject stale completion
- authenticated mission stop remains terminal admission control
- execution session authority remains independently activated, bounded, and
  revocable

No record in this module substitutes for those controls. A target action must
pass both high-availability safety admission and the existing authorization
stack.

## Deliberate boundaries

This module does not:

- implement Raft, Paxos, leases, heartbeats, or leader election
- start a process or thread, read a system clock, or contact a peer
- connect to a database or persist an epoch, grant, or observation
- acquire a distributed lock or enforce a fencing token
- dispatch scheduler, outbox, control-plane, or target work
- authorize a write, fail over a service, or activate a degraded mode
- qualify a deployment or prove availability, durability, or recovery

Production completion still requires a selected and deployed consensus or
coordination substrate, an atomic PostgreSQL persistence implementation,
independent failure domains, authenticated peer identities, bounded clock
behavior, durable fencing enforcement at every writer, load balancer and worker
integration, mission-stop propagation, observed failover exercises, split-brain
fault injection, recovery evidence custody, monitoring, and independently
reviewed qualification results.

## Schema

`registry/schemas/ha-coordination-contract-v1.schema.json` validates all ten
top-level records with closed fields and closed no-effect values. Application
code must still use the Python parser and cross-record evaluators to verify
content addresses, identity bindings, monotonicity, quorum, lease time, fence,
and recovery semantics.
