# Supplied z/OS Grant Policy

The GC-D16-S01 partial component compares synthetic opaque grant triples with
a supplied policy for the z/OS specialist lane. Its checked example is
[`examples/offline-zos-grants-component.json`](../examples/offline-zos-grants-component.json).

No RACF, CICS, Db2, mainframe, credential, or network is accessed. The model
does not parse native authority records or prove effective privileges. A
mismatch is a caller-asserted policy discrepancy, not an exploitation finding.
The result is nonqualifying R0 evidence and grants no authority.
