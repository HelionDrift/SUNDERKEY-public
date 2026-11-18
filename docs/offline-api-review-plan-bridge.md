# Offline API review and planning bridge

The review-plan bridge is a compact packet for independent human reviewers.
It replays both the synthetic API planning bundle and the proposal-only review
handoff from their original typed sources. It requires the same batch digest,
verified scope digest, and tenant supplied by the trusted caller.

The packet links pending review candidates to immutable case-result digests,
the planning bundle, schedule, and proposed task digests. It does not assert
that a task produced a finding or that a reviewer accepted the case. The
status remains `awaiting_independent_human_review`, and the finding state is
`not_published`.

The bridge has no assignment, notification, execution, review-decision, or
finding-publication effect. Its content address is an integrity aid, not
source-origin authentication. A later finding or report workflow must use
fresh authorization, independently verified work products, and an actual
independent review decision.
