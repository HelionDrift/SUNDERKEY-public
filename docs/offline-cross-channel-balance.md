# Supplied cross-channel balance

The `AOE-GB-D09-S12` partial specialist replays caller-supplied debit and
credit records against one local opening balance. It distinguishes accepted
from rejected records, flags repeated accepted transaction references, marks
when a repeated reference crosses channel labels, and compares each declared
balance with local arithmetic. Accepted records are counted even when flagged.

The exact native JSON model declares `schema_version: 1`,
`semantics_profile: supplied-cross-channel-balance-v1`, an opaque digest-shaped
account reference, a caller-supplied currency label, an opening balance in
integer minor units, and one to 512 ordered entries. Entries declare a unique
event ID, channel ID, opaque transaction reference, debit or credit kind,
positive amount, accepted or rejected result, and declared balance. Structure,
values, and report size are bounded. The typed report can be replayed against
current supplied input.

Account, channels, transaction identity, outcomes, amounts, currency, and order
are caller assertions. Repeated references are review signals, not proof of
duplicate settlement or a real economic effect. No account, payment,
credential, service, network, or target is contacted. The component grants no
action authority or qualification. The [synthetic example](../examples/offline-cross-channel-balance-component.json)
uses only fictitious references and a fictitious currency label.
