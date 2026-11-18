# Supplied SocketCAN Classical Frame Projection

The GD-D19-S12 partial component checks bounded, synthetic, little-endian
SocketCAN `struct can_frame` records. It reports classical data-frame ID
widths, IDs, payload lengths, and payload digests. The checked example is
[`examples/offline-socketcan-classical-frames-component.json`](../examples/offline-socketcan-classical-frames-component.json).

The record layout and flag masks follow the Linux
[`can.h` UAPI](https://github.com/torvalds/linux/blob/master/include/uapi/linux/can.h).
This component excludes remote-request, error, and CAN FD frames. It
does not interpret payload bytes as UDS or any other higher-layer
protocol. A supplied CAN ID does not establish a vehicle, ECU, bus,
or observed behavior.

No frame is acquired from or sent to an interface or target. No
finding or qualification is produced. Independent verification replays
the separate original model.
