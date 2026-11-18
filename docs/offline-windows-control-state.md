# Supplied Windows Security-Control State Projection

The GC-D11-S13 partial component compares at most 64 synthetic endpoint
protection, tamper protection, firewall, or audit state declarations with a
supplied required-enabled list. Separate verification replays the original
supplied model. A required control absent from the supplied inventory leaves
the disposition unknown even when completeness is asserted.

The policy, state declarations, and completeness are unverified assertions.
The component does not read or alter Windows or EDR controls, access a host,
or prove impairment. A declared mismatch is a review signal, not a finding.
It grants no authority or qualification.

The checked synthetic example is
[`examples/offline-windows-control-state-component.json`](../examples/offline-windows-control-state-component.json).
