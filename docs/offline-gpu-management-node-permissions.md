# Offline GPU Management Node Permissions

This R0 component projects the `mig-config` capability from caller-supplied
NVIDIA MIG access-control declarations. NVIDIA documents that `mig-config`
controls MIG instance creation and destruction. Root or `CAP_SYS_ADMIN` has
implicit access to NVIDIA capabilities. For the `/dev` capability interface,
the projection requires both a declared cgroup device-read grant and a declared
device-node read grant. For the deprecated `/proc` interface, it requires both
declared namespace visibility and read permission. These rules are grounded in
the [NVIDIA MIG Device Nodes and Capabilities Guide](https://docs.nvidia.com/datacenter/tesla/mig-user-guide/device-nodes-and-capabilities.html).

The model names one interface and at most 64 principals. Each principal has a
caller-supplied expected capability value. A difference is an unsigned,
nonqualifying candidate about that declaration only. Incomplete inventory
returns unknown. A projected capability does not establish that a principal
can successfully reconfigure a GPU.

The component does not inspect device nodes, cgroups, namespaces, GPU state,
driver version, or real identities. It performs no management action. Exported
reports require replay against the original supplied model for verification.
