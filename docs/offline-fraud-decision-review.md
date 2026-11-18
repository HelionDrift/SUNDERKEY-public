# Supplied fraud decision review

The `AOE-GB-D09-S10` partial specialist compares caller-supplied coarse
risk-band decisions with caller-supplied minimum action labels. It separately
flags a declared floor that differs from the model and a decision below the
model floor. Stronger decisions are not treated as contradictions.

The exact native JSON model declares `schema_version: 1`,
`semantics_profile: supplied-fraud-decision-review-v1`, an opaque policy
reference, minimum allow, challenge, or block action for low, medium, and high
bands, and one to 512 decision records. Each record has a unique ID, opaque
subject reference, coarse band, declared minimum, and decision. Structure,
values, and report size are bounded. The typed report can be replayed against
current supplied input.

Policy, risk bands, subject labels, and decisions are caller assertions. The
model has no scoring features, production rules, or evasion sequence. A
mismatch does not prove fraud, a bypass, or live control effectiveness. No
account, payment, credential, service, network, or target is contacted. The
component grants no action authority or qualification. The [synthetic example](../examples/offline-fraud-decision-component.json)
uses only fictitious references.
