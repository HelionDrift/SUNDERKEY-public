# Supplied IBM i Grant Policy

The GC-D16-S02 partial component compares synthetic opaque grant triples with
a supplied policy for the IBM i specialist lane. Its checked example is
[`examples/offline-ibmi-grants-component.json`](../examples/offline-ibmi-grants-component.json).

No IBM i host, object authority record, credential, or network is accessed.
The model does not establish effective access or an exploitable path. A
mismatch is a caller-asserted policy discrepancy, not an exploitation finding.
The result is nonqualifying R0 evidence and grants no authority.
