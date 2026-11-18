# Supplied RNG Sample Consistency

The GE-D22-S08 component counts exact repeated values, adjacent equal pairs,
and one-bits at each position in at most 256 caller-supplied 8, 16, 32, or
64-bit samples. Sample IDs must be unique and values must use lowercase,
fixed-width hexadecimal. It reports repeated sample IDs, not raw values.

The supplied sequence may be incomplete. Repetitions and bit counts do not
estimate entropy, certify randomness, demonstrate a cryptographic weakness,
or constitute a finding. No generator or target is observed, and no candidate,
qualification, or live authority is created.

The checked synthetic example is
[`examples/offline-rng-sample-component.json`](../examples/offline-rng-sample-component.json).
Verification requires replay against the separate original model.
