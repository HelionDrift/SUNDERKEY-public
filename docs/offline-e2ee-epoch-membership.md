# Supplied E2EE Epoch Membership

The GE-D22-S13 component projects membership joins and departures and compares
each epoch's member IDs with its declared key-envelope recipient IDs. It accepts
at most 16 ordered epochs with at most 64 members and 64 recipients per epoch.

Epoch order, membership and recipient lists are unverified assertions. Missing
or excess recipients are declaration mismatches, not proof of a key-distribution
flaw or loss of confidentiality. No envelope, key, message, user, or target is
observed. The result grants no finding, qualification, or action authority.

The checked synthetic example is
[`examples/offline-e2ee-epoch-component.json`](../examples/offline-e2ee-epoch-component.json).
Verification requires replay against the separate original model.
