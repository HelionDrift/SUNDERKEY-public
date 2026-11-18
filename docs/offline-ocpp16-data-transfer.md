# Supplied OCPP 1.6 DataTransfer Projection

The GD-D25-S04 partial component inspects a bounded, synthetic OCPP 1.6
DataTransfer CALL request. The [Open Charge Alliance customization whitepaper](https://openchargealliance.org/wp-content/uploads/2025/05/OCA-Customizing-OCPP-Implementations.pdf)
describes the required `vendorId`, optional `messageId` and `data` string,
and reverse-domain vendor naming. The checked example is
[`examples/offline-ocpp16-data-transfer-component.json`](../examples/offline-ocpp16-data-transfer-component.json).

The component checks the four-element CALL shape and a constrained
DataTransfer payload. Its size and character limits are local safety bounds,
not a full OCPP conformance claim. It hashes identifiers and data instead
of retaining them. A syntactically plausible vendor ID does not prove vendor
identity, a customization agreement, receiver support, or charging behavior.

No message is sent to a charging station or management system. No finding or
qualification is produced. Independent verification replays the separate
original model.
