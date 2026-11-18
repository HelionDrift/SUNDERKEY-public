# Supplied CCSDS Space Packet Projection

The GD-D25-S08 partial component inspects a bounded, synthetic CCSDS Space
Packet primary header. [CCSDS 133.0-B-2](https://ccsds.org/Pubs/133x0b2e2.pdf)
defines the six-octet header, version, packet type, secondary-header flag,
APID, sequence control, and packet-data length. The checked example is
[`examples/offline-ccsds-space-packet-component.json`](../examples/offline-ccsds-space-packet-component.json).

The component checks version zero and exact packet-data length, projects the
header fields, and hashes rather than retains packet data. It does not parse
mission-specific secondary headers or user data. An APID is unique only
within its naming domain, and a telecommand type bit does not establish a
valid command or execution. No link-layer integrity or spacecraft identity
is verified.

No packet is acquired from or sent to a target. No finding or qualification
is produced. Independent verification replays the separate original model.
