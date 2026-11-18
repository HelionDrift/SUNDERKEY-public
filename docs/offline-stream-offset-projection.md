# Supplied stream offset projection

The `AOE-GB-D07-S08` partial specialist compares a caller-supplied partition
range with observed offset numbers and an ordered list of declared processing
commits. It reports duplicates, compressed unlisted intervals, commit
regressions, and an abstract lag against a supplied threshold. If history is
marked incomplete, unlisted intervals remain unknown rather than missing.

The exact native JSON model uses `schema_version: 1`,
`semantics_profile: supplied-stream-offsets-v1`, an opaque partition digest,
integer range, completeness assertion, up to 512 observed offsets, and up to
256 commits. There is no message body, broker URL, consumer credential, or
real timestamp. Native type and byte bounds apply. The typed report replays
from its supplied model.

Offsets, order, commits, and completeness are unauthenticated caller
statements. Unlisted intervals do not prove broker record loss. A declared
commit does not prove consumer processing. No broker, provider, credential,
network, or target is contacted. The report grants no action authority or
qualification. The [synthetic example](../examples/offline-stream-offset-component.json)
uses only fictitious opaque references.
