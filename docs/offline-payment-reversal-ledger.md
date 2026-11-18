# Supplied payment reversal ledger

The `AOE-GB-D09-S04` partial specialist replays a caller-supplied payment
capture followed by ordered refund and chargeback records. Accepted reversals
reduce a local remaining amount; rejected records do not. The report flags an
accepted reversal total above the supplied capture and any mismatch with the
declared remaining amount. It does not infer why a reversal was rejected.

The exact native JSON model declares `schema_version: 1`,
`semantics_profile: supplied-payment-reversal-ledger-v1`, a digest-shaped
opaque payment reference, a caller-supplied currency label, a positive capture
in integer minor units, and one to 512 unique ordered reversal records. Each
record declares an event ID, refund or chargeback kind, positive amount,
accepted or rejected result, and remaining amount. Structure, values, and
report size are bounded. The typed report can be replayed against current
supplied input.

Capture, currency semantics, payment reference, event order, and outcomes are
caller assertions. A mismatch is a review signal, not proof of processor
behavior, a refund defect, settlement, or economic impact. No payment,
account, credential, service, network, or target is contacted. The component
grants no action authority or qualification. The [synthetic example](../examples/offline-payment-reversal-component.json)
uses only fictitious references and a fictitious currency label.
