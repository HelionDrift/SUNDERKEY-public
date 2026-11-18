# Supplied Sudo Grant-Policy Projection

The GC-D12-S03 partial component compares at most 64 synthetic normalized
sudo-grant declarations with caller-supplied root-access policies for at most
32 command labels. It flags a declared root grant to a principal outside a
policy's allowed list or without a required password declaration. Separate
verification replays the original supplied model.

All principals, command labels, grants, policies, and completeness values are
unverified assertions. The component does not parse sudoers, PAM, or polkit
configuration, read a host, run a command, request credentials, or attempt a
privilege change. A declared mismatch is not proof of executable elevation.
This first slice does not model the complete specialist profile and cannot
grant authority, publish a finding, or qualify it.

The checked synthetic example is
[`examples/offline-sudo-grant-component.json`](../examples/offline-sudo-grant-component.json).
