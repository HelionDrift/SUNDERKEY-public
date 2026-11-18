# Supplied Flash Region-Map Projection

The GD-D18-S07 partial component projects at most 64 synthetic flash-region
declarations within a supplied flash-size bound. It reports interval overlaps,
regions outside the declared size, and sensitive or credential-material regions
whose supplied metadata omits a protection declaration. Separate verification
replays the original supplied model.

All offsets, lengths, classes, protections, and completeness values are
unverified caller assertions. A declared mismatch is not a verified device
vulnerability. The component does not read an image, connect to a device,
remove a chip, access a bus, or inspect a target. It cannot grant authority,
publish a finding, or qualify a specialist.

The checked synthetic example is
[`examples/offline-flash-region-component.json`](../examples/offline-flash-region-component.json).
