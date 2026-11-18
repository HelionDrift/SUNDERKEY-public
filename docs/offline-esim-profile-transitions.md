# Supplied eSIM Profile Transitions

The GC-D13-S20 partial component compares synthetic, opaque profile-state
transitions with a supplied allowed-transition policy. Discontinuous event
sequences remain unknown. Its checked example is
[`examples/offline-esim-profile-transitions-component.json`](../examples/offline-esim-profile-transitions-component.json).

The model accepts no subscriber identifier or provisioning material. It does
not contact an eUICC, provisioning service, or mobile network, and it changes
no profile. Transitions and completeness remain assertions, not effective
device state. This is nonqualifying R0 evidence and grants no authority.
