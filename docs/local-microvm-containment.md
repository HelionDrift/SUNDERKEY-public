# Local microVM containment fixture

This repository-only increment implements work queue item WQ-003 as an exact,
nonexecuting Firecracker-style containment specification. It closes the design
gap between the candidate adapter execution plan and a future Linux microVM
executor without claiming that Firecracker, jailer, KVM, or an external host is
available.

## Contract binding

`build_local_microvm_execution_spec` accepts an existing microVM
`ContainmentExecutionPlan` and `ContainmentBackendDeploymentBinding`. It
verifies both content addresses, requires the `jailed_firecracker`
implementation target, confirms the backend attestation binding, and carries
the candidate runner limits into one content-addressed specification.

The checked-in fixture intentionally does not contain a passing host preflight.
Its host-preflight contract records:

- the exact deployment binding ID and digest;
- the external status required before dispatch;
- a null observed report ID and digest;
- `not_observed_fixture` as the observed status; and
- a mandatory external preflight before any dispatch.

`validate_external_host_preflight` is a read-only compatibility check for a
future caller. It verifies that a supplied host-preflight report binds the same
deployment and has the required content-addressed result. It does not dispatch
anything or alter the specification.

## Firecracker-style specification

The execution specification encodes all of the following controls:

- content-pinned guest kernel and base root filesystem;
- a read-only base root filesystem;
- a bounded, ephemeral overlay that must be removed after execution;
- exact Firecracker and jailer paths;
- a safe jailer chroot path and a dedicated non-root UID and GID;
- jailer seccomp level 2 and a new PID namespace;
- an explicit `/dev/kvm` requirement;
- Linux, cgroup v2, host-hardening, and bounded-logging requirements;
- a single-tenant VM with simultaneous multithreading disabled;
- CPU, memory, PID, output, log, overlay, and time ceilings;
- no network interfaces, tap devices, or metadata service;
- no credential references or host environment forwarding;
- fail-closed cancellation, deadline, teardown, and residual-effect policies;
- exact jailer argument construction; and
- no qualification, routing, deployment, or target-authority effects.

The kernel, root filesystem, and security inputs are specifications only. The
module never opens those files, resolves devices, creates an overlay, checks
KVM, starts a process, or uses a socket.

## Injected executor boundary

`LocalMicrovmRuntimeAdapter` is a protocol for a later external implementation.
It defines execution, cancellation, and teardown methods. This repository-only
module never calls that protocol. A future adapter must separately validate a
passing host preflight, materialize the content-pinned artifacts, enforce the
encoded limits outside the guest, and return independently verifiable evidence.

The protocol boundary prevents the fixture from being mistaken for a deployed
containment system. A Python object that satisfies the protocol is not evidence
that an external isolation boundary exists.

## Deterministic receipt

`build_local_microvm_containment_fixture` creates a content-addressed fixture
receipt with four canonical observations:

1. The specification encodes the required containment controls.
2. Firecracker, jailer, KVM, network, credentials, and host state were not used.
3. Cancellation, teardown, and residual-effect observation were not exercised.
4. Host preflight, external containment, qualification, and authority remain
   unchanged.

The receipt always states that host preflight did not pass, runtime execution
did not occur, external containment was not proven, output and log byte counts
are zero, teardown did not start, and residual effects were not observed. This
is deliberate. A deterministic repository fixture can prove serialization and
policy construction, but it cannot prove hardware-backed containment.

## Validation and tamper resistance

The Python parsers reject unknown or missing fields, unsafe paths, malformed
hashes, inconsistent plan and binding identities, substituted jailer arguments,
root identities, out-of-range budgets, and any non-none operational effect.
Specification, observation, and receipt identities are derived from canonical
JSON and domain-separated SHA-256 digests.

`registry/schemas/local-microvm-containment-fixture-v1.schema.json` is a Draft
2020-12 schema for all three serialized artifact kinds. Focused tests validate
round trips, schema conformance, content substitution rejection, exact budget
propagation, lifecycle controls, and rejection of a blocked external host
preflight.

## Remaining infrastructure work

This increment does not provide external containment. Completing that work
still requires a dedicated Linux host with KVM, approved Firecracker and jailer
binaries, pinned and patched guest artifacts, dedicated host identities,
bounded storage and logging, production cancellation and teardown controls,
host preflight, dynamic conformance, signed evidence collection, and operational
review. Those infrastructure results remain separate from this nonqualifying
repository fixture.
