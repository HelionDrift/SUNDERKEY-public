# Supplied OSDP Poll Frame Review

The GA-D02-S10 partial component validates one bounded synthetic plain
OSDP `CMD_POLL` frame. The [LibOSDP packet structure](https://doc.osdp.dev/protocol/packet-structure)
defines its header and checksum fields, and its
[command list](https://doc.osdp.dev/protocol/commands-and-replies) identifies
`CMD_POLL`. The checked example is
[`examples/offline-osdp-poll-frame-component.json`](../examples/offline-osdp-poll-frame-component.json).

It checks the start byte, physical address, length, control flags, command
code, and checksum. The constrained frame contains no card data or secure
channel block. Checksum consistency does not authenticate a device or prove
badge acceptance, access grant, or physical entry. No packet is transmitted,
reader contacted, finding published, or qualification claimed.
