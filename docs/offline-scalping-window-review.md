# Supplied scalping window review

The `AOE-GB-D09-S09` partial specialist replays caller-supplied per-actor
allowed and blocked allocation records in aligned fixed windows. It flags an
allowed count above a supplied per-actor limit and differences from the
declared count. Blocked records do not advance the local allowed count.

The exact native JSON model declares `schema_version: 1`,
`semantics_profile: supplied-scalping-window-review-v1`, an opaque item
reference, positive window duration and per-actor limit, and one to 512
ordered records. Each record has a unique ID, opaque actor reference,
nondecreasing integer second, allowed or blocked result, and declared count.
Structure, values, and report size are bounded. The typed report can be
replayed against current supplied input.

Item and actor labels, clock, order, outcomes, and limits are caller
assertions. A mismatch does not prove automation, scalping, allocation,
control failure, or economic impact. The component contains no bot evasion
logic. No item, account, marketplace, service, network, or target is contacted.
It grants no action authority or qualification. The [synthetic example](../examples/offline-scalping-window-component.json)
uses only fictitious references.
