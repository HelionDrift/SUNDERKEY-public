# Supplied Mailbox-Forwarding Policy Projection

The GC-D11-S15 partial component compares at most 64 synthetic mailbox
forwarding declarations with caller-supplied external-forwarding and
destination-domain policies. It flags active declarations that the supplied
policy disallows. Separate verification replays the original supplied model.

Mailbox identities, forwarding states, destination labels, policies, and
completeness are unverified assertions. This component does not parse or
verify Exchange Online tenant configuration, connect to a tenant, read a
mailbox, or send a message. A declared mismatch is not evidence of delivered
mail or data exposure. It cannot grant authority, publish a finding, or
qualify the specialist.

The checked synthetic example is
[`examples/offline-mailbox-forwarding-component.json`](../examples/offline-mailbox-forwarding-component.json).
