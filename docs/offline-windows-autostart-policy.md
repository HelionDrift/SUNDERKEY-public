# Supplied Windows Autostart Policy Projection

The GC-D11-S09 partial component compares at most 64 synthetic service,
scheduled-task, Run key, startup-folder, and WMI-subscription declarations
with a supplied artifact allowlist. An enabled artifact outside that list is
marked for review. Separate verification replays the original supplied model.

The inventory, approval list, and completeness are unverified assertions.
This component does not inspect autoruns, access a host, execute an artifact,
or prove persistence. A declared mismatch is not a finding. It grants no
authority or qualification.

The checked synthetic example is
[`examples/offline-windows-autostart-component.json`](../examples/offline-windows-autostart-component.json).
