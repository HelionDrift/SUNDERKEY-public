# Supplied SIP Dialog Sequence Projection

The GC-D13-S13 partial component accepts at most 64 synthetic event labels
for one caller-declared, nonforked SIP dialog. It models an illustrative
INVITE, optional provisional responses, successful INVITE response, ACK,
BYE, and successful BYE response sequence with caller-supplied CSeq values.
It reports deviations from this narrow state model and requires separate
original-model replay. The sequence is informed by [RFC 3261](https://www.rfc-editor.org/rfc/rfc3261).

This is not a SIP parser or conformance validator. Forking, retransmission,
failure responses, early dialogs, tags, transport, routing, SDP, RTP, and
other valid SIP behavior are outside its model. Events and completeness are
unverified assertions; a deviation is not a vulnerability finding. No packet,
media stream, SIP endpoint, credential, or target is accessed. The component
grants no authority and has no qualification effect.

The checked synthetic example is
[`examples/offline-sip-dialog-component.json`](../examples/offline-sip-dialog-component.json).
