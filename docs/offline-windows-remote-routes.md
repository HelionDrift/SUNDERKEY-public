# Supplied Windows Remote-Route Policy Projection

The GC-D11-S12 partial component compares at most 64 synthetic WinRM, WMI,
RDP, or SMB session declarations with caller-supplied source-to-destination
route approvals. Separate verification replays the original supplied model.

Host IDs, routes, sessions, and completeness are unverified assertions. The
model does not establish reachability or authorization, open a session, use a
credential, or interact with any host. A route mismatch is a review signal,
not proof of lateral movement or a vulnerability finding. It grants no
authority or qualification.

The checked synthetic example is
[`examples/offline-windows-remote-routes-component.json`](../examples/offline-windows-remote-routes-component.json).
