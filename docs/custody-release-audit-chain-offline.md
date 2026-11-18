# Release audit chain, offline reference only

`CustodyReleaseAuditChain` implements the existing D012
`ReleaseAuditSink.append_audit_event` interface by composing explicit injected
`RetentionLockedLedgerObjectProvider` and `ConditionalLedgerHeadProvider` ports.
It does not add an operation or change an existing request or receipt protocol.
There is no default transport, cloud SDK, file store, network client, credential
resolver, signer, deployment operation or target operation. Its environment is
`reference_simulation_nonqualifying`.

The ports must declare that reference environment and expose every existing
required operation. A Python protocol or environment label is a declaration,
not authenticated origin or evidence of production storage controls. Inject
only bounded synthetic reference ports for this implementation boundary.

## Explicit construction

The constructor requires all of these inputs without policy defaults:

- `ledger_objects` and `ledger_heads`: the two existing complete custody ports;
- `namespace_id`, `failure_domain_id`, and `deployment_id`: the dedicated declared
  audit object domain and logical head coordinate;
- `retention_until`: one fixed whole-second UTC protection horizon;
- `clock`: an explicit callable returning an exact timezone-aware `datetime`;
- `maximum_traversal_records`, `maximum_provider_calls`, `maximum_read_bytes`,
  and `maximum_object_bytes`: explicit per-operation resource ceilings.

The implementation subset caps records at 16 KiB and chains at 4,096 events.
Traversal permits at most 8,193 records per operation, provider calls at most
16,400, and accepted read payload bytes at most 8,193 times 16 KiB. These are
software bounds, not approved operational retention, cost, capacity or account
limits. Larger protocol values are not silently converted or truncated.

Identifiers and stored metadata use native printable ASCII, counters use native
bounded integers, and boolean counter aliases, floats and unsupported typed
subclasses fail before source normalization. Requests and every returned receipt
are reconstructed through exact existing D012 families, including nested values.
The exact validated configuration is bound to its construction-time canonical
digest. Later substitution of a different valid horizon, domain, coordinate or
resource ceiling fails before the clock or custody ports are called. This local
source binding is not authentication of those declarations.
The clock is checked before and after each provider call and before a receipt.
Expired horizons and backwards operation clocks block consumption.

Every derived head read, object read, protection read, upload and conditional
head update is captured through its exact D012 request family. Providers receive
an owned copy, including independently owned nested descriptors. Primitive
receipt-correlation values are pinned before callbacks. Both the original and
dispatched request must remain identical to the unexposed capture before a
success or rejection can be consumed, including typed conflicts and transport
errors. A changed request cannot redefine which operation was acknowledged.
These checks do not undo any storage effect already performed by a callback.

## Sequence allocation and immutable history

Each prepared record contains the exact public `ReleaseAuditEventDescriptor`,
logical audit sequence, recorded time, declared domain and fixed horizon, plus
the complete prior logical `LedgerHeadDescriptor`. Its canonical JSON SHA-256
defines its immutable `audit.DIGEST` object identity. It contains no raw target
evidence, credentials or signature. Actor identity remains public caller-supplied
metadata, not an authenticated actor grant.

An immutable upload is preparation only. It never allocates or acknowledges a
sequence. After a confirmed object upload, digest read and current retention
check, the adapter attempts exactly one conditional logical-head transition.
Only an exact successful CAS receipt followed by fresh bounded chain and
protection reconstruction can acknowledge the transition. Provider generations
are owned by the injected ports, not substituted for audit sequence numbers.

Cold reconstruction follows the content-addressed prior-head links all the way
to sequence one. Every object must reproduce its digest, declared domain,
exact fixed horizon, sequence, event, chronology and predecessor. Every consumed
object gets a fresh retention/deletion-protection read. The current head must
remain unchanged around reconstruction. Duplicate event IDs, gaps, foreign
heads, changed bytes, deleted records and shortened protection fail closed.

An existing event ID with the same complete event returns
`already_appended_same_digest` and its original sequence, including after later
events or a cold instance. The same event ID with changed content is a conflict;
it cannot obtain a new sequence. Each instance also retains its highest validated
head and requires subsequent views to include that exact head, rejecting an
observed-history rollback or fork.

## Races, uncertainty and bounded settlement

Before the first write, the adapter reserves the known provider calls, traversal
records and payload reads needed to settle the proposed append. Concurrent chain
growth can still exceed a bound; exhaustion never becomes an acceptance claim.
The byte ceiling governs locally accepted read payloads, not a network-stream
limit on an arbitrary injected provider. The port has no streaming-size parameter.
Each returned payload has an additional fixed pre-hash bound.

A correctly bound `ledger_head_conflict` is a confirmed CAS loss. The adapter
does not retry the write. It reconstructs the current winner once: an identical
committed event can return its original sequence, while a different winner is
a conflict. The losing uploaded object can remain an orphan. An orphan is not
an audit record, a sequence allocation or permission to sign a release. The
adapter does not delete or adopt orphan objects automatically.

A lost object acknowledgement, timeout, ambiguous head application, invalid
receipt or unrelated denial yields no audit receipt. Mere object readback cannot
upgrade an unknown write outcome. If a head was applied before its acknowledgement
was lost, an explicit later caller replay can reconstruct the committed event.
There is no automatic retry, confirmed rollback, deletion or cross-object
transaction. Storage exceptions and uncertainty are not fabricated policy-denial
evidence.

## Authority and conformance limits

The isolated audit tests compose the unchanged D012 case 11 operations for
audit-before-sign and failure blocking, alongside direct reference probes for
replay, original event
collisions, CAS winners/losers, orphan uploads, lost acknowledgements, retention,
source changes and bounds. This isolated case execution is not a complete D012
conformance report. Its signer is the existing simulated digest fixture, not a
real signature or root-authorized release service.

A separate complete reference-composition fixture combines the GCS ledger,
head and catalog adapters with this audit chain across all twelve unchanged
D012 cases. Dedicated synthetic audit custody coordinates keep audit-head
advancement separate from release-head state. Audit transport failure or a lost
upload/head acknowledgement blocks signing; it does not become a confirmed
rollback. The full report remains reference-only and nonqualifying. The added
composition neither changes the normative case catalog nor supplies approved
production signing bytes, authenticated provider enforcement or live acceptance.

The adapter cannot make independent storage services atomic or authenticate
their currentness, actor identity, namespace, failure domain or retention claims.
A fresh instance cannot detect an internally consistent rollback of the entire
provider view without an independently trusted current-head anchor. Current
monotonic head behavior remains an obligation of the existing head provider;
same-instance high-water checking is not durable anti-rollback authority.

Real retention and legal-hold policy, dedicated service identities, storage
domains, protected head anchors, authenticated observations, release signing,
complete production conformance and D014 activation remain external. No
reference receipt establishes accepted ingest, qualification, production
custody, release authorization or live readiness.
