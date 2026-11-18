# Supplied SAP Grant Policy

The GC-D16-S04 partial component compares synthetic opaque grant triples with
a supplied policy for the SAP specialist lane. Its checked example is
[`examples/offline-sap-grants-component.json`](../examples/offline-sap-grants-component.json).

No NetWeaver, ABAP, HANA, user, credential, or network is accessed. The model
does not parse SAP authorization objects or establish effective privileges.
A mismatch is a caller-asserted policy discrepancy, not an exploitation
finding. The result is nonqualifying R0 evidence and grants no authority.
