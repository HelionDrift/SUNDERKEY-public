# Artifact recording input integrity

This repair keeps one caller-supplied artifact plan coherent across the existing
recorder and injected PostgreSQL artifact facade. It does not add a schema,
record domain, authority operation, storage lifecycle or database deployment.

## Owned input boundaries

Before any port lookup or invocation, `record_artifact` replays the supplied
exact `ArtifactRecordingPlan` into a detached valid original. It retains private
canonical observation expectations and the original plan/batch IDs and hashes.
The port receives a separately detached plan, never the private original or its
expectation. The returned exact `ArtifactCommitObservation` is also replayed and
detached before comparison and receipt construction.

The PostgreSQL `commit_artifact` facade independently validates and detaches its
plan and request before invoking its injected connection factory. Its committed
batch and returned request metadata therefore derive from the same owned plan.
The existing transaction, row/document joins, historical claim snapshot checks,
cleanup policy and 23 literal SQL statements are unchanged.

A pre-entry plan whose request, batch or derived identity was changed without
matching reconstruction rejects before the port/factory is called. Explicit
Python reassignment of the caller's frozen plan or request during a callback
does not rebind the owned original. Mutation of the plan delivered to a port
does not alter the recorder's private comparison or receipt identities. A
foreign observation still rejects even if the port changes its delivered plan
to a different internally valid plan.

These are input-ownership and at-use consistency rules, not a remote exploit
claim or a sandbox for arbitrary Python code. Ordinary native mismatched plan
construction and coherently readdressed mismatched plan JSON already reject.
The reproduced callback gap required deliberate `object.__setattr__` mutation.
The repair does not promise detection of all coherent changes before entry,
concurrent caller mutation during capture, monkeypatched implementations or
arbitrary inspection of private process memory.

## Bounded metadata and compatibility

Supported record parsing and consumption require native scalar values and
exact wrapper families. Incomplete slots, aliases/subclasses, floats, duplicate
JSON fields and booleans where integer metadata is required reject through the
existing leaf errors. Each supplied record document has a 64 KiB canonical ASCII
JSON budget, depth 12 and 4096-node ceiling. Repeated shared subtrees, JSON string
escapes and punctuation are charged before hashing or serialization. Integer
conversion is also locally bounded. Wrapper traversal is bounded before its
document is assembled. These are per-document software-cost limits, not artifact
size, lease, tenant, retention or authorization limits.

Valid existing schema-one plans, observations and receipts retain their exact
IDs, hashes and canonical bytes. Existing first-custody, optional-outbox and
explicit replay behavior remains supported. This boundary introduces no live
clock or new historical/current-authority checks. Caller authority, admission
and adapter selection remain separate responsibilities.

## One-call and failure boundary

The recorder invokes its port once. It does not retry, refund or repair a failed
or mismatching result. A port may already have committed before its observation
is rejected; this rejection does not prove external rollback or absence of an
effect. The PostgreSQL facade retains the existing explicit uncertain-outcome
handling for failed commit acknowledgement or post-commit cleanup.

The receipt is metadata consistency against the requested content address and
an adapter observation, not independent authenticity, proof that artifact bytes
exist, recoverability, retention enforcement or qualification. No bundled
SQLite `commit_artifact` facade is introduced by this repair.

`tests/agents/test_artifact_recording_input_integrity.py` uses genuine existing
Phase 169 public fixtures and the original inert Phase 170 `FakeStore`. It
checks pre-entry denials, caller and delivered-plan mutation, foreign committed
metadata followed by observation rejection, native/bounded inputs, original
golden bodies, round trips and PostgreSQL replay. These fixtures perform no
database-engine, network, provider, target, credential or deployment operation.
