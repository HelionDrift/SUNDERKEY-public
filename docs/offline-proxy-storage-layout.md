# Offline Proxy Storage Layout

This R0 component supports a narrow part of `AOE-GB-D10-S07`. It compares explicitly supplied, bounded linear single-slot storage layouts for a prior and next implementation. A stable field ID is checked for changes in slot, byte offset, size or normalized semantic type digest. Newly declared fields are checked for byte overlap with prior fields. A removed field remains unknown because reserved storage or migration may preserve compatibility.

The model does not compile Solidity, read contracts, deploy upgrades, or cover namespaced and dynamic layouts. Its field IDs, byte positions and type digests are supplied and unauthenticated. The resulting collision candidates are consistent with [OpenZeppelin's storage-layout compatibility guidance](https://docs.openzeppelin.com/upgrades-plugins/writing-upgradeable), but they are not a substitute for compiler output or an upgrade validator. A candidate does not prove deployment or value corruption.

Reports omit supplied type digests, retain only bounded field dispositions and a source digest, and require original-model replay. No finding, qualification, execution or positive-use authority is established.

Example: [`examples/offline-proxy-storage-layout-component.json`](../examples/offline-proxy-storage-layout-component.json).
