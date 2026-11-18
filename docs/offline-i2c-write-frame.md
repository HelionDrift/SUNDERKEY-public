# Supplied I2C Write-Frame Projection

The GD-D18-S06 partial component projects at most 64 synthetic event declarations
for one controller write. It tracks a narrow START, address byte, acknowledgment,
data byte, acknowledgment, and STOP sequence. A negative acknowledgment may
precede STOP. The address octet must carry a write-direction bit. Separate
verification replays the original supplied model.

Event identity, byte values, ordering, completeness, and write intent are
unverified assertions. A declared framing deviation is not a captured bus
error or vulnerability. Reads, repeated starts, arbitration, clock stretching,
electrical timing, and SPI are outside this model. No bus, device, hardware,
credential, or target is accessed. This projection cannot grant authority,
publish a finding, or qualify the specialist.

The narrow sequence follows the frame concepts in the
[NXP I2C-bus Specification and User Manual](https://www.nxp.com/docs/en/user-guide/UM10204.pdf),
without claiming conformance. The checked synthetic example is
[`examples/offline-i2c-write-component.json`](../examples/offline-i2c-write-component.json).
