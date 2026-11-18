# Supplied Windows Privilege Artifact Projection

The GC-D11-S08 partial component compares at most 64 synthetic service,
scheduled-task, or startup-artifact declarations. It marks an artifact when
both privileged execution and lower-privilege write access are declared.
Separate verification replays the original supplied model.

The artifact inventory, execution context, write access, and completeness are
unverified assertions. This component does not inspect ACLs, access a host,
execute an artifact, or prove privilege escalation. A declared overlap is a
review signal, not a finding. It grants no authority or qualification.

The checked synthetic example is
[`examples/offline-windows-privilege-artifacts-component.json`](../examples/offline-windows-privilege-artifacts-component.json).
