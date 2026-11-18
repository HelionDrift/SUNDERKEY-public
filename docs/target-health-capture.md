# Supplied target-health receipt capture

`target_health_capture` composes existing target-health receipt, root-signed
collector policy, V2 envelope and custody contracts. It reads supplied canonical
receipt bytes through an injected source and publishes a collector-signed
envelope through an injected custody port. It does not probe or contact targets,
select roots or operational policy, own signing keys, open a store, resume or
pause execution, or grant authority or qualification. These are limits of the
driver's built-in behavior. A caller-supplied concrete custody implementation
may persist local signed records; software tests use disposable existing SQLite
custody. That local persistence does not establish target, provider, production
or independent acceptance evidence.

The [pinned local file source](pinned-local-health-receipt-source.md) is one
read-only implementation of the injected source port for explicitly supplied
files. Its byte pins do not authenticate telemetry or change capture authority.

## Explicit inputs and finite workflow

`capture_target_health_receipts` requires an exact `TargetHealthTrustRoot`, exact
`TargetHealthCollectorPolicyRevision`, source, signer, custody port, existing
`AdapterStopState`, caller UTC clock, native UTC deadline, and explicit individual
receipt-byte, total-byte and source-call limits. Nothing has an operational
default. Clock values and deadline are native whole-second UTC `datetime` values.
The local ceilings are 128 source calls, 1 MiB per supplied document and 128 MiB
total supplied bytes. They are software-cost limits, not target authorization.

The source implements `read_receipt(*, maximum_bytes)` and returns native bytes
or `None`. Every call, including exhaustion and failure, is charged before
invocation. Native byte lengths are charged before parsing. Oversized or invalid
input does not reach signing or append. The workflow does not inspect or execute
any artifact beyond the existing receipt JSON contract.

Each iteration prepares the existing durable signing context before reading
the source. A nonempty supplied receipt must exactly replay its canonical bytes,
including native scalar types, and match the policy's complete execution binding
and runtime policy. The workflow refreshes signing context immediately before
signing and compares every field except `prepared_at`. Changed policy, epoch,
sequence, predecessor, binding or head halts; it is not adopted or retried.
Sequence follows the durable global chain head, including across collector epochs.
Context preparation reserves nothing.

A sequence-one context must satisfy the unchanged V2 epoch predecessor rule
before reading a source or signing. Within one invocation, a later context cannot
precede its latest confirmed envelope. The same sequence must name that exact
confirmed envelope and digest. A higher external head is permitted; missing
intermediate lineage remains custody-owned, not independently authenticated.

Existing policy validity and evidence age, future-skew and embedded-expiry rules
are checked before signing and append. The injected signer accepts the unchanged
V2 signing bytes and must return exactly 64 native bytes. The resulting envelope
is verified cryptographically with the owned policy's Ed25519 public key before
append. No signature wrapper, schema, record domain or custody lifecycle changes.

## Ownership, acknowledgement and uncertainty

Root, policy, context, receipt and acknowledgement wrappers are bounded, replayed
and detached. The recorder keeps a private attempted envelope and hands a
separately detached envelope to custody. Deliberate mutation of caller inputs or
delivered objects cannot rebind that private expectation. This is a cooperative
input-ownership boundary, not an arbitrary Python process-memory sandbox or
concurrent mutation guarantee.

A returned exact append result must reconstruct its receipt and event and match
the private envelope, root, policy, binding, runtime policy, epoch, sequence,
predecessor and health-receipt identity. Verification and recording must not
predate refreshed context or the pre-append clock. The event must name that exact
custody receipt and envelope and share its recording time and sequence. A known
contiguous event within this invocation must link the previous confirmed event.

When the single existing post-append clock call supplies a new native,
nonregressing UTC sample, acknowledgement verification and recording cannot be
after that sample. The sample remains available if a subsequent stop, deadline
or policy check halts. A contradiction rejects only that provisional publication,
retains the prior confirmed prefix and restores the original attempted envelope
as uncertain. A stop before that clock call, or a failed, invalid or regressing
clock, supplies no upper bound and does not erase an otherwise valid
acknowledgement. The pre-append time is never used as that upper bound.

The two-method custody port does not provide a prior event body on restart or a
full revocation document. Unknown prior event lineage and scheduled revocation
references remain custody-owned claims, not independently reconstructed durable
truth. Local envelope current verification at the acknowledged acceptance time
does not independently prove a durable head, absent revocation, target health,
production storage or future permission. The existing custody implementation
must still perform its own atomic currentness, head, revocation and race checks.

The result contains in-memory confirmed publications, observed call/byte counts,
terminal stage and sanitized reason. Any append callback exception, malformed
acknowledgement or mismatch conservatively retains the original uncertain
attempted envelope. It makes no rollback, absence-of-effects or retry claim.
An otherwise validated acknowledgement is provisionally retained before
post-append cancellation, deadline, clock or policy checks. Those later checks
do not erase known progress unless an available new post-callback timestamp
contradicts the acknowledgement. This changes no external record or rollback
state.

## Cooperative stop and cost boundaries

Cancellation, emergency stop, deadline and nonregressing clock checks surround
every injected callback. Failure permits no subsequent source, signer or custody
call. These checks cannot interrupt a blocking callback. There are no sleeps,
automatic retries, probes, refunds, fallback policy, automatic resume or observer.
The caller may separately use existing `observe_current`; that is not atomic
with this workflow and conveys no automatic control authority.

Native metadata replay rejects incomplete or subclassed wrappers, aliased
scalars, non-native keys, floats, nonfinite values, duplicate JSON keys and
booleans where integers are required. Every document has a 1 MiB serialized-byte,
8192-node and depth-24 budget; repeated subtrees, escaped strings and punctuation
in supplied documents are charged before replay, serialization or hashing.
Strings and integers are bounded before costly conversion. The combined owned
unsigned envelope and existing signing shape are bounded before the placeholder
constructor derives identity; its complete generated document and native signing
bytes are also bounded before the signer is invoked. Existing constructors still
derive their original IDs. These bounds do not reinterpret retention or source
policy, and existing valid V2 bodies and IDs remain unchanged.

Rejected health receipts and completed adverse observations may be recorded
under their unchanged contracts. Publication never upgrades them to healthy,
safe, independently authenticated target observations, qualification or execution
permission. Live sources, keys, custody resources and independent acceptance
remain caller and infrastructure responsibilities.
