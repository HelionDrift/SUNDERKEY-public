# Offline API retest transition bridge

The retest transition bridge joins the existing two-case synthetic comparison
to the cross-batch source ledger and child attack-world snapshot. It replays
the selected prior case, requires that case's result and evidence digests in
the prior ledger, compares it with a distinct second case, and appends the
second batch through the replay-aware lineage operation.

The result binds the observation-change label to both lineage digests and the
child world snapshot. For a positive-to-negative synthetic retest, the label
means only that the prior signal was not observed in the second case. The
earlier hypothesis and the new negative observation remain in the child
world as a conflict. It does not assert a remediation, independently reviewed
finding, or verified exploitation path.

Review status remains `not_reviewed`, remediation remains `not_claimed`, and
all authority, execution, review-decision, and publication effects are none.
Original sources and current authority are still required for any positive
use outside this offline comparison.
