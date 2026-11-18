# Supplied AIS Position Report Projection

The GD-D25-S07 partial component inspects a bounded, synthetic, 168-bit AIS
Class A position report of type 1, 2, or 3. [ITU-R M.1371-6](https://www.itu.int/dms_pubrec/itu-r/rec/m/R-REC-M.1371-6-202602-I%21%21PDF-E.pdf)
defines the field widths and reserved ranges. The checked example is
[`examples/offline-ais-position-report-component.json`](../examples/offline-ais-position-report-component.json).

The component rejects unsupported message types, reserved spare bits, and
out-of-range coordinates. It reports field availability and hashes the
source ID and communication state instead of retaining a vessel identifier
or coordinates. A position-accuracy or RAIM bit is only a reported claim;
no vessel identity, radio capture, positioning accuracy, navigation state,
or maritime safety outcome is verified.

No radio data is acquired or transmitted. No finding or qualification is
produced. Independent verification replays the separate original model.
