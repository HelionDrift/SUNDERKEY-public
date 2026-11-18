# Supplied coupon redemption timeline

The `AOE-GB-D09-S07` partial specialist replays a bounded caller-supplied
coupon event sequence. It keeps separate global and per-actor counts. For
accepted records it flags counts beyond supplied limits and duplicate
accepted order labels. It also compares each declared post-event count with
the local projection. Rejected records do not increment counts.

The exact native JSON model declares `schema_version: 1`,
`semantics_profile: supplied-coupon-redemption-timeline-v1`, digest-shaped
opaque coupon, actor, and order references, positive global and per-actor
limits, and one to 512 ordered accepted or rejected events. Event IDs are
unique. All input and report sizes are bounded. A typed report replays the
embedded model and supports independent verification against current input.

Coupon policy, identities, order labels, outcomes, and event order are all
caller assertions. Digest-shaped references do not prove independent
pseudonymization or custody. A count anomaly is a review observation, not
proof of a real coupon defect, fraud, or economic impact. The component does
not redeem coupons, place orders, contact a target, use credentials, change a
ledger, grant action authority, or qualify a candidate. The
[synthetic example](../examples/offline-coupon-redemption-component.json)
contains only fictitious opaque references.
