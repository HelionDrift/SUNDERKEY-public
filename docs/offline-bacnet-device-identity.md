# Offline BACnet Device Identity

This R0 component supports a narrow part of `AOE-GD-D19-S17`. It decodes caller-supplied 32-bit BACnet Device Object_Identifiers into object type and instance fields, then groups duplicate instances within one declared internetwork. A review candidate requires a complete supplied inventory and the same instance assigned to distinct supplied device rows. The [BACnet Committee's object model overview](https://bacnet.org/wp-content/uploads/sites/4/2022/06/BACnet-A-standard-communication-infrastructure-for-intelligent-buildings-1.pdf) describes internetwork-wide Device Object_Identifier uniqueness; its [encoding example](https://bacnet.org/wp-content/uploads/sites/4/2022/08/Encoding.pdf) identifies Device object type 8.

The component does not read packets, query a BACnet device, resolve proxies, or authenticate inventory rows. Repeated supplied rows may be duplicate records rather than distinct devices. A collision signal does not prove spoofing or operational impact.

The unsigned report requires separately retained original-model replay and grants no finding, qualification, or positive-use authority.

Example: [`examples/offline-bacnet-device-identity-component.json`](../examples/offline-bacnet-device-identity-component.json).
