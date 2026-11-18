# Offline GPU Instance Tenant Boundary

This R0 component checks caller-supplied GPU Instance and Compute Instance
assignments for mixed tenants within one GPU Instance. Multiple Compute
Instances inside one GPU Instance share that GPU Instance's memory and engine
resources, as described in the
[NVIDIA MIG User Guide](https://docs.nvidia.com/datacenter/tesla/mig-user-guide/concepts.html).
It compares the projected single-tenant status with a caller-supplied
expectation. A mismatch is only an unsigned, nonqualifying candidate.

The analysis does not inspect a GPU, parse device nodes, verify scheduler or
driver behavior, prove hardware isolation, or determine whether co-tenancy is
authorized. An incomplete topology returns unknown. Original-model replay is
required to verify the report.
