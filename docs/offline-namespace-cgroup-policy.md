# Supplied Namespace and cgroup Policy Projection

The GC-D12-S07 partial component compares at most 64 synthetic workload
declarations with at most 16 caller-supplied tenant policies. It identifies
declared namespace labels shared across tenants whose policy requires
separation, and memory-limit declarations above the corresponding supplied
tenant maximum. Separate verification replays the original supplied model.

Tenant IDs, namespace IDs, memory limits, and policy are unverified assertions.
A shared label does not prove shared kernel isolation or escape. A declared
memory-limit mismatch does not prove actual usage or denial of service. The
component does not inspect a host, enter a namespace, alter a cgroup, start a
process, or contact a target. It cannot grant authority, publish a finding,
or qualify the specialist.

The checked synthetic example is
[`examples/offline-namespace-cgroup-component.json`](../examples/offline-namespace-cgroup-component.json).
