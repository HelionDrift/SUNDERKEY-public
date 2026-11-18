# Supplied debit idempotency timeline

The `AOE-GB-D09-S03` partial specialist replays a bounded caller-supplied
sequence of accepted and rejected debit records against one declared opening
balance. It separately flags a duplicate accepted command label, an accepted
debit exceeding the currently derived available balance, and a declared
post-event balance that differs from the local arithmetic. Rejected events
do not debit the local balance. The original event order and source labels
remain visible in the replay report.

The model has exact fields `schema_version: 1`,
`semantics_profile: supplied-debit-idempotency-timeline-v1`, opaque
`account_ref`, `currency_label`, `initial_balance_minor`, and `events`. It
accepts one to 512 events with unique IDs, command labels, positive bounded
debit amounts, `accepted` or `rejected` results, declared post-event balances,
and source labels. The account reference is digest-shaped, but its origin
from an independent random identifier is not proven. The typed report replays
its source model and supports current-input verification.

This is arithmetic over assertions, not an observed race or real double
spend. Source custody, event order, outcomes, account balances, idempotency
policy, and currency semantics are not authenticated. A negative derived
balance or duplicate accepted label is a review signal only. No account,
ledger, payment, credential, financial transaction, target, qualification,
or publication is used. The
[synthetic example](../examples/offline-debit-idempotency-component.json)
contains only fixture records.
