# Supplied Windows Administration Invocation Projection

The GC-D11-S10 partial component classifies at most 64 synthetic PowerShell,
WMI, COM, or LOLBin invocation declarations against a supplied approval list.
It marks a privileged-context declaration outside that list for review.
Separate verification replays the original supplied model.

The invocation inventory, family, context, approval, and completeness are
unverified assertions. No command text is parsed or executed, and no host,
credential, or target is accessed. The result does not prove unauthorized
activity or constitute a finding. It grants no authority or qualification.

The checked synthetic example is
[`examples/offline-windows-admin-invocations-component.json`](../examples/offline-windows-admin-invocations-component.json).
