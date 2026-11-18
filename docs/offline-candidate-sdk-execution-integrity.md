# Offline candidate SDK execution integrity

This repair strengthens the existing approved D016 synthetic SDK and contained
execution evidence contracts. It adds no adapter family, target access,
credentials, production key, provider call, deployment or qualification grant.

## Reciprocal boundaries

The public reference adapter requires the exact native `True` dry-run value
before its analyzer runs. Truthy integers, floats and strings do not establish
the synthetic dry-run boundary.

The ICS reference analyzer compares canonical JSON state, rather than Python
dictionary equality. Boolean, integer and floating-point state changes remain
distinct, including nested changes. An actual change preserves a failed-closed
restoration status and the synthetic residual-effect record. Reordered object
keys with unchanged canonical values remain equivalent.

Containment-plan replay reconstructs the admitted plan and checks the exact
native primitive shape and canonical document. An equal-valued Boolean or float
schema version cannot retain the original integer-schema plan identity.
Containment limits require native integers within their existing bounds.

One shared receipt check is applied to producer output and historical receipt
replay. It enforces native integer counters and Boolean flags, the existing
result and restoration vocabularies, whole-second UTC times, nonnegative exact
elapsed duration, the original plan validity window and output ceiling, and the
producer's timeout/cancellation fail-closed and derived run-status rules. A finish
exactly at plan expiry, zero elapsed duration and zero reported output retain
their previous valid semantics. No new hash domain, receipt field or port is
introduced.

Packet construction checks that the receipt finish is no later than packet
creation. The existing collector and signed importer reconstruct through that
same packet layer. Their packet-to-collection, challenge and observation joins
remain unchanged. Correct hashes and a genuine collector signature do not make
an impossible execution timeline valid.

## Historical and adverse evidence

Historical replay checks execution against the original plan window. It does not
require an old plan to remain current at verification time. Any separate current
collector-challenge conditions still apply at their existing boundary.

Timeout, cancellation, abstention, failed-closed restoration and residual-effect
records remain representable and replayable when internally consistent. Their
preservation is not clean-execution qualification. The existing signed importer
still rejects adverse execution when it requires a clean completed result.

This is metadata consistency, not independent proof that an external backend
enforced containment or that its output-byte declaration measured actual output.
It does not establish signing-key authority, provider acceptance or real-target
authorization. Arbitrary hostile Python code in the same process is not a
containment boundary.

## Regression evidence

The focused test module exercises the actual public adapter path, unchanged-ID
native plan aliases, correctly readdressed receipt documents, backend output
aliases, preserved adverse records and exact valid timing boundaries. Disposable
synthetic Ed25519 fixtures sign readdressed malicious packets before invoking the
public evidence importer. Impossible duration, pre-plan start, post-plan finish
and finish-after-packet creation are rejected independently of signature or hash
corruption. A valid historical execution still verifies after its original plan
expires.

Fixed historical native plan and receipt vectors preserve their prior identities
and hash domains. Those manifest bytes are historical test inputs, not a claim
that their old source digest admits changed code. Current-source tests build a
genuine in-memory catalog from the source under test. The release integration
must regenerate the checked-in source-bound catalog and dependent records after
the source repair.
