# Offline Firmware Emulation Trace Projection

This R0 component covers a narrow declaration-only slice of `AOE-GD-D18-S02`.
It compares caller-supplied emulator architecture and trace digest labels with
caller-supplied expected labels. A difference is an unsigned divergence
candidate, not a firmware defect. Missing labels or incomplete fixture, trace,
or inventory context produce `unknown` rather than a candidate.

The component does not open or execute firmware, start an emulator, contact a
device, or verify the origin of a trace. It establishes neither runtime
behavior, exploitability, a finding, nor qualification. Replay verification
requires the separately retained original model.

The [synthetic example](../examples/offline-firmware-emulation-trace-component.json)
uses fictitious image and digest labels and no target resources.
