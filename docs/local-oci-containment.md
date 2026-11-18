# Local OCI containment fixture

This increment implements roadmap work item WQ-002 as a repository-only local
OCI containment contract. It produces an exact rootless Podman-style execution
specification and deterministic fixtures. It does not start Podman, run a
process, open a socket, contact a network, handle credentials, interact with a
target, or mutate host runtime state.

## Existing contract bindings

The builder requires the canonical Phase 157 inputs for one candidate action:

- an adapter manifest and invocation;
- an OCI containment backend attestation;
- the corresponding containment execution plan;
- the containment conformance suite catalog;
- the exact deployment binding and host snapshot;
- a passing read-only host-preflight report.

Every source object is reparsed through its existing exact-field verifier. The
builder rejects a noncanonical object, a substituted content address, a blocked
preflight, a microVM contract, or an inconsistent attestation binding.

A passing preflight only permits creation of the repository fixture. It does
not establish that Podman is installed, that a host is available, or that the
specified controls work on an external runtime.

## Exact OCI specification

The content-addressed execution specification fixes all of these controls:

- a registry-qualified image pinned by SHA-256 digest;
- rootless Podman with an automatic user namespace and a non-root container
  user;
- a read-only root filesystem;
- all Linux capabilities dropped;
- no-new-privileges;
- a content-addressed seccomp profile;
- private PID, IPC, and cgroup namespaces;
- network mode `none`;
- no host devices and no host bind mounts;
- a fixed environment that does not import host credentials;
- an ephemeral, nonexecutable tmpfs workspace with a byte ceiling;
- explicit CPU, memory, PID, output, workspace, and time ceilings;
- fail-closed cancellation with a one-second grace period;
- required container and workspace cleanup with residual-state verification;
- content-addressed JSON observations only.

The specification includes exact Podman arguments so host integration cannot
silently weaken a declared control. The argument vector is data. This module
does not pass it to a shell, subprocess, runtime library, or service.

## Injected runtime boundary

`LocalOciRuntimeAdapter` defines the future host-side execution, cancellation,
and cleanup interface. No function in this module calls that protocol. A later
host integration must inject an implementation, enforce the exact
specification, publish bounded observations, and pass the existing external
conformance and evidence-import checks.

This split keeps the repository fixture useful before infrastructure exists
without pretending that a data model is an enforcement boundary.

## Deterministic observations

The fixture contains three content-addressed observations:

1. The repository validated the specification and encoded its controls.
2. No runtime execution occurred and an injected adapter is still required.
3. Qualification, routing, deployment, and target authority remain unchanged.

The observation set is canonical. Reordering, replacing, adding, removing, or
rehashing an observation is rejected. Both the observation records and the
fixture state explicitly say that external containment was not proven.

## Safety and qualification boundary

Every specification, observation, and fixture has all four operational effects
set to `none`. The fixture cannot:

- qualify a candidate or containment backend;
- route work to an agent or runtime;
- deploy an adapter or create a container;
- authorize a target, action, credential, or network path;
- substitute for external containment evidence.

The external Linux host, exact Podman deployment, service identity, dynamic
conformance probes, signed evidence, and independent qualification remain
infrastructure work.

## Artifacts

- `src/sunderkey/local_oci_containment.py`
- `tests/agents/test_local_oci_containment_phase169.py`
- `registry/schemas/local-oci-containment-fixture-v1.schema.json`
- `docs/local-oci-containment.md`

The JSON Schema uses Draft 2020-12 and rejects additional fields at every
contract layer. Python parsers also reconstruct identities from canonical JSON,
verify exact fields and semantic invariants, and reject content substitution.
