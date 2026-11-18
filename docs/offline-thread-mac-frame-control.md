# Supplied Thread MAC Frame-Control Projection

The GD-D18-S14 partial component decodes only the two-byte IEEE
802.15.4 frame-control word supplied as synthetic hex. Its bit fields
follow [OpenThread's MAC frame implementation](https://github.com/openthread/openthread/blob/main/src/core/mac/mac_frame.hpp):
frame type uses bits 0 through 2, security-enabled bit 3,
ack-requested bit 5, destination address mode bits 10 and 11,
version bits 12 and 13, and source address mode bits 14 and 15.
The checked example is
[`examples/offline-thread-mac-frame-control-component.json`](../examples/offline-thread-mac-frame-control-component.json).

A supplied policy can flag a data-frame word without the
security-enabled bit. The bit being set does not establish encryption,
message-integrity verification, valid key use, Thread membership, or
Matter behavior. Reserved field values and incomplete input inventory
remain uncertain. This component does not parse a complete MAC frame,
process payload bytes, receive or transmit radio traffic, or contact a
device. It is not a security finding or a qualified capability.

Independent verification replays the separate original synthetic
word inventory. Malformed words, duplicate IDs, and nonsynthetic
input are rejected.
