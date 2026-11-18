# Supplied Pattern Review Handoff

The review handoff converts a separately replayed
[pattern claim graph](offline-pattern-claim-graph.md) into bounded human
challenge work. Each claim retains its source, premise, relation digest,
task-result digest, current catalog owner, commander, and independent
validator reference. Hypotheses list their contributing claims and reviewer
references. These are references, not assignments or accepted reviews.

The handoff first replays every original relation and task against the current
catalog. A verifier repeats that derivation and rejects modified packet
contents, including positive-use or review-acceptance flags. Matching claims
request source-scope and premise challenges, contradictions request
resolution, and unresolved claims request missing evidence. The packet is
unsigned, records no operational effects, and cannot publish a finding,
authorize target interaction, or qualify a candidate.
