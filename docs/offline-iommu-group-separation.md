# Offline IOMMU Group Separation

This R0 component supplies a narrow part of `AOE-GD-D24-S04`. It compares caller-supplied device trust roles and IOMMU group memberships. A supplied group containing both protected and untrusted DMA-capable devices, or a declared disabled IOMMU with an untrusted DMA-capable device, becomes a review candidate only for a complete supplied inventory. The [Linux kernel VFIO documentation](https://docs.kernel.org/driver-api/vfio.html) explains IOMMU groups as isolation and ownership units and cautions that topology and interconnects can reduce effective isolation.

The source does not authenticate group IDs, IOMMU state, ACS behavior, bridge topology or DMA reachability. It cannot prove access across a group or device compromise. No PCIe, Thunderbolt, DMA, IOMMU or host interface is touched.

The unsigned report requires separately retained original-model replay and grants no finding, qualification or positive-use authority.

Example: [`examples/offline-iommu-group-separation-component.json`](../examples/offline-iommu-group-separation-component.json).
