# Supplied MAVLink 2 Packet Envelope Projection

The GD-D25-S10 partial component inspects a bounded, synthetic, supplied
MAVLink 2 packet. The [MAVLink packet serialization guide](https://mavlink.io/en/guide/serialization.html)
defines the magic byte, header, payload length, checksum field, and optional
13-byte signature field used for envelope geometry. The checked example is
[`examples/offline-mavlink2-packet-envelope-component.json`](../examples/offline-mavlink2-packet-envelope-component.json).

This component rejects unknown incompatibility flags, inconsistent packet
lengths, and zero sender IDs. It hashes the payload and records header fields.
It does not verify the CRC because the message definition and CRC_EXTRA are
not supplied. A present signature is not authenticated. Sender IDs do not
establish an aircraft or trusted source, and the payload is not interpreted.

No packet is acquired from or sent to a target. No finding or qualification
is produced. Independent verification replays the separate original model.
