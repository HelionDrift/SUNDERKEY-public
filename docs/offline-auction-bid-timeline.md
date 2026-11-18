# Supplied auction bid timeline

The `AOE-GB-D09-S08` partial specialist replays a caller-supplied ordered
auction bid record. It keeps a local leading bidder and amount after each
accepted record. It separately flags accepted bids below a supplied minimum
increment, rejected bids meeting that local increment, and mismatches against
the declared leader and amount. A supplied reserve comparison is reported
separately. Accepted records advance the local projection even when flagged.

The exact native JSON model declares `schema_version: 1`,
`semantics_profile: supplied-auction-bid-timeline-v1`, an opaque digest-shaped
listing reference, caller-supplied currency label, reserve and minimum
increment in integer minor units, and one to 512 ordered bid events. Each
event has a unique ID, opaque bidder reference, positive bounded bid amount,
accepted or rejected result, and declared leading bidder and amount. Inputs,
native structure, strings, and reports are bounded. The typed report can be
replayed against current supplied input.

Listing, bidder identity, currency semantics, reserve, increment, event
order, and outcomes are all caller assertions. A mismatch is a review signal,
not proof of a real auction winner, marketplace defect, fraud, or economic
impact. No listing, bidder, auction, payment, credential, service, or target
is contacted. The component grants no action authority or qualification.
The [synthetic example](../examples/offline-auction-bid-component.json)
contains only fictitious references and a fictitious currency label.
