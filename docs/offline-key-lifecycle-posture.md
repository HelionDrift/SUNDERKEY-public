# Supplied Key Lifecycle Posture Review

The GE-D22-S10 component compares a small, closed model of supplied key
lifecycle dates. It is an unsigned R0 review aid. It never contacts an HSM or
KMS, reads key material, evaluates effective provider policy, or grants target
authority. A finding, candidate qualification, or routing decision cannot be
based on this report alone.

The model declares one UTC snapshot time and up to 32 uniquely named keys.
Each key supplies a state, creation time, optional last rotation and last use,
optional destruction time, optional rotation interval, and an explicit policy
completeness assertion. Times use exact `YYYY-MM-DDTHH:MM:SSZ` syntax and must
fall within the supplied creation-to-snapshot interval. Destroyed keys require
a destruction time; other states prohibit one. Unknown rotation policy and
incomplete inventory remain visible as uncertainty.

Two narrow review signals are possible. An active key whose supplied age since
creation or last rotation exceeds its supplied interval has a declared elapsed
rotation interval. A destroyed key with a supplied last-use time after its
supplied destruction time has a declared chronological mismatch. Neither
signal proves actual key use, compromise, effective rotation, or provider state.
The report includes only key identifiers, signal labels, counts, a model digest,
and false effect flags. It requires separate replay against the original model.

The checked synthetic envelope is
[`examples/offline-key-lifecycle-posture-component.json`](../examples/offline-key-lifecycle-posture-component.json).
It requests no resources and makes no operational call. Supply inert metadata
only, retain the original source for review, and do not treat a caller-supplied
timestamp as trusted time.
