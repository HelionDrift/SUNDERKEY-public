# Supplied Linux Shell-Tool Policy Projection

The GC-D12-S05 partial component compares at most 64 synthetic shell,
interpreter, or system-tool invocation declarations with a supplied approval
list for privileged contexts. Separate verification replays the original
supplied model.

Tool families, contexts, approvals, and completeness are unverified
assertions. The component does not parse or execute commands, access a host,
or verify effective privileges. An approval mismatch is a review signal,
not an exploitation finding. It grants no authority or qualification.

The checked synthetic example is
[`examples/offline-linux-shell-component.json`](../examples/offline-linux-shell-component.json).
