# Supplied account recovery threshold

The `AOE-GB-D09-S05` partial specialist compares caller-supplied recovery
attempt labels with a caller-supplied threshold over digest-shaped enrolled
factor references. It separately flags accepted attempts below the supplied
threshold, accepted attempts containing an unenrolled factor label, rejected
attempts meeting the supplied threshold, and mismatches between result and
declared reset flag. The original model and each attempt remain in the
replay-checked report.

The exact native JSON model declares `schema_version: 1`,
`semantics_profile: supplied-account-recovery-threshold-v1`, an opaque
digest-shaped account reference, one to 64 distinct enrolled factor labels,
a required count from one to eight, and one to 256 attempts. Each attempt has
a unique ID, up to eight distinct presented factor labels, accepted or
rejected result, and a declared reset flag. Input and report sizes are
bounded. The typed report supports replay against current supplied input.

Factor labels are not credentials. Their enrollment, possession, independence,
freshness, and the real recovery policy are not authenticated. A threshold
anomaly does not prove a deployed weakness or account takeover. This
component does not assess KYC, trigger recovery, contact an account or target,
use credentials, authorize positive use, or qualify a candidate. The
[synthetic example](../examples/offline-account-recovery-component.json)
contains only fictitious factor references.
