# Supplied macOS Security-Control Projection

The GC-D12-S10 partial component compares synthetic TCC, SIP, and Gatekeeper
state declarations with a supplied required-enabled list. A required control
absent from the supplied inventory leaves the disposition unknown. Separate
verification replays the original supplied model.

Policy, states, and completeness are unverified assertions. No macOS control
state is read or changed. A declared mismatch does not prove bypass or
impairment, and it is not a finding. The component grants no authority or
qualification.

The checked synthetic example is
[`examples/offline-macos-security-controls-component.json`](../examples/offline-macos-security-controls-component.json).
