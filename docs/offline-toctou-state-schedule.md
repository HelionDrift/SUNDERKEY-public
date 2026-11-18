# Supplied Check-Use State Schedule

The `AOE-GE-D23-S10` partial specialist projects a finite, caller-supplied
version schedule. It ties a check to an actor and resource, requires every
resource to have an initial version, and counts declared version-advancing
mutations between that check and a later use. A use must reference a preceding
check owned by the same actor and resource.

When the policy declares stale checks must be rejected, complete asserted
event and observation premises with an intervening version change and a
declared accepted outcome yield only a
`candidate_declared_stale_check_conflict`. An incomplete schedule, incomplete
policy or capture, unknown outcome, or check version inconsistent with the
declared version at check time withholds that conclusion. This is a sequential
projection of assertions. It does not measure concurrency, prove a race or
TOCTOU exploit, or establish actual target state.

The model permits at most 32 initial resources and 128 events within a 64 KiB
native document bound. Opaque `ref:` labels are format guards, not proof that
supplied content was sanitized. The report embeds the original model for
separate-source replay. No file, network, process, credential, target,
publication, execution, or qualification effect occurs. The
[synthetic example](../examples/offline-toctou-state-schedule-component.json)
contains only declared events.
