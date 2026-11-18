# Offline Operator Offboarding Review

This partial GA-D02-S13 algorithm compares synthetic personnel termination, account disable, and privileged-event timestamps. It records review cues when a declared privileged event follows termination or account disable. [NIST SP 800-53 Revision 5, AC-2 Account Management](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final) is the source for treating account lifecycle records as a control concern, but this component does not evaluate control compliance or organizational offboarding deadlines.

The records are supplied by the caller, not authenticated. Clock alignment, person-to-account binding, exceptional authorization, event origin, actual account use, and intent are unknown. A cue is not an insider-abuse finding. Opaque person and account references are hashed in the output.

The fixture is synthetic, R0, dry-run, and has no credential or resource grants. Original-model replay is required. No personnel system, account, or audit service is queried or changed. The result grants no operational authority or qualification.
