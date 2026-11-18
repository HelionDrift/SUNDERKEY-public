# Cloud and identity specialist adapter contracts

`sunderkey.specialist_cloud_identity_adapters` defines the repository-only
adapter boundary for roadmap packages C4.3 through C4.8. It provides fixed
provider profiles, content-addressed requests, an injected adapter protocol,
result attestation bindings, receipts, and a process-local replay guard. It
does not provide cloud SDKs, identity provider clients, network transports,
credential resolution, unrestricted administration, or remote execution.

The increment is not qualified. Passing its unit tests proves deterministic
contract behavior against fake adapters only.

## Provider-neutral capability families

The policy table binds every operation to one package, mutation class, and
minimum action tier:

| Package | Family | Representative operations |
| --- | --- | --- |
| C4.3 | Identity provider | Policy and federation reads, federation validation |
| C4.4 | Cloud control plane | Inventory read, reversible configuration probe |
| C4.5 | Workload identity | Binding read, identity validation, ephemeral identity |
| C4.6 | Cloud IAM | Role session validation, temporary role binding |
| C4.7 | Container orchestration | Kubernetes RBAC read |
| C4.8 | Data platform | Metadata read and safe access proof |

Read-only operations require at least R1. Validation operations require at
least R2. Reversible mutation operations require at least R3, explicit
mutation approval, a nonzero mutation budget, and any dry-run behavior
required by the approval.

## Fixed provider profiles

`provider_profile_declarations` returns profiles for AWS, Azure, GCP,
Kubernetes, Microsoft Entra ID, Okta-style federation, generic SaaS tenancy,
and serverless or container surfaces. Each profile lists its supported
operations, required scope dimensions, and dry-run capable operations.

AWS requires an exact account reference, Azure requires a subscription
reference, GCP requires a project reference, and Kubernetes requires a cluster
reference. Every request also binds the tenant and signed scope. A request for
an unsupported operation or one missing a profile-required dimension fails
before an adapter can run.

## Exact authority and session binding

`SpecialistActionRequest` binds all of these values into its content address:

- tenant, account, project, subscription, cluster, and signed scope references;
- mission, worker, admitted action, and action admission digest;
- provider profile, operation, mutation class, and requested tier;
- exact approval reference and digest;
- exact leased session, principal, session digest, and provider;
- evidence references and evidence digests;
- idempotency key, dry-run flag, budget, and validity window.

The approval must bind the same context, provider, operation, and a sufficient
tier. The session must bind the same context and provider. Current validity is
checked immediately before adapter invocation. Context, approval, session, or
provider substitution fails closed.

The contract carries only opaque references and digests. Passwords, tokens,
cookies, private keys, raw credentials, commands, and exploit text have no
request fields and common secret patterns are rejected.

## Injected execution and result attestation

`CloudIdentityExecutionAdapter` is a runtime-checkable protocol. The caller
must inject an implementation whose immutable identity declares one provider
and its supported operations. SUNDERKEY validates the request before the first
adapter call.

The adapter returns `AdapterObservation`. It must repeat the exact request,
context, scope, approval, session, and idempotency bindings. It also reports
bounded operation, resource, mutation, and evidence counts. A result
attestation reference and digest are mandatory. If a reversible operation
reports a mutation, restoration evidence is mandatory.

`SpecialistActionReceipt` preserves those facts in a deterministic content
address. It does not claim that the result attestation was signed by trusted
hardware or independently verified. Those are infrastructure and assurance
responsibilities.

## Replay, idempotency, and bounded effects

`SpecialistReplayGuard` reserves the idempotency key before adapter execution.
A repeated key is rejected without a second adapter call. Production use must
replace the process-local set with a durable atomic replay store while
preserving the same behavior.

Requests set explicit ceilings for operations, resources, mutations, and
evidence items. Adapter observations above any ceiling fail closed. Read and
validation classes require a zero mutation budget and reject any reported
mutation. R3 is limited to operations classified as reversible mutations and
requires restoration evidence when a mutation occurs.

## Remaining infrastructure and qualification work

This repository increment does not make C4.3 through C4.8 operational. Live
use still requires approved provider selections, least-privileged identities,
credential custody, authorized tenants and resources, cloud and identity
transports, production replay and budget storage, monitoring, durable evidence
custody, cleanup automation, emergency stop enforcement, and independent
qualification. No unit test in this increment contacts a cloud service,
identity provider, Kubernetes cluster, SaaS tenant, or workload runtime.
