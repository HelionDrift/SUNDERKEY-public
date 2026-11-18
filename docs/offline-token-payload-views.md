# Supplied Token Payload View Review

The GE-D22-S11 component compares inert token-payload JSON bytes with up to
eight caller-supplied parser claim views. It performs one local strict JSON
decode with duplicate-key rejection, then compares canonical claim digests.
The report never includes raw payload bytes or claim values. It includes only
payload and view digests, parser identifiers, bounded signal labels, and
explicit uncertainty. A parser view is an assertion, not an observed run of
that parser.

The synthetic example has two same-name JSON keys and two different asserted
parser views. This creates a review question about potential ambiguity. It
does not prove a signature bypass, target token acceptance, authorization
impact, or any exploitable pathway. Different software may implement different
parsing and signing rules. This component does not execute that software or
verify a signature. It is unsigned and nonqualifying.

Use only inert or sanitized supplied data. Do not place real bearer tokens,
secrets, or personal claims in this model. The checked envelope is
[`examples/offline-token-payload-views-component.json`](../examples/offline-token-payload-views-component.json).
No network, credential, process, provider, or target resource is requested.
Original-model replay is required before consuming the local report.
