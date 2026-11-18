# Supplied Custom Protocol Framing

The GE-D22-S12 partial component compares at most 64 synthetic byte frames with
one caller-supplied framing hypothesis. The hypothesis gives byte offsets and
one- or two-byte widths for a message-kind field and a payload-length field.
The component extracts direction-kind pairs and identifies frames whose stated
payload length differs from the supplied frame bytes. It rejects overlapping
fields, short frames, duplicate frame IDs, and ambiguous encodings.

This is an inert structural projection, not protocol reverse engineering from
a target. Field meanings, capture completeness, and the hypothesis itself are
unverified assertions. A length mismatch does not establish a parser defect or
an exploitable condition. No frame is sent, no endpoint is contacted, and no
finding, qualification, or action authority is granted.

The checked synthetic example is
[`examples/offline-custom-protocol-framing-component.json`](../examples/offline-custom-protocol-framing-component.json).
Verification requires replay against the separate original model.
