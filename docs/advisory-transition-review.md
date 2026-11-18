# Advisory applicability transition review

This repository-only V9.4 slice compares two applicability reports for the
same supplied advisory and tenant. Each report must bind to its matching
reconciled asset snapshot, and the current snapshot must be a direct
descendant of the baseline. Snapshot, report, and review times must advance
in order. The comparison is content-addressed and has no network, scheduler,
execution, finding-publication, authority, or remediation-confirmation effect.

Before relying on a stored transition, `verify_advisory_transition_report_from_sources`
recomputes both applicability reports from the supplied component observations,
then recomputes the transition. A report with a valid self-hash can otherwise
carry a false-negative applicability state. Source replay rejects that state,
omitted or changed supplied observations, and altered transition rows. It
does not authenticate sources or prove the supplied observations are complete.

The transition vocabulary is intentionally conservative:

- `new_or_returned_candidate_match`: a candidate match is present in the
  current report but was not present in the baseline;
- `continuing_candidate_match`: a candidate match appears in both reports;
- `candidate_match_not_reobserved`: a baseline match is replaced by current
  evidence whose exact version is not listed by the advisory;
- `current_evidence_gap`: a baseline match no longer has usable current
  component or asset evidence; and
- `review_state_changed`: a non-match review state changed without an exact
  candidate match.

An absent match is not a verified remediation. A new or returned match is not
proof of a regression or exploitability. Confirming either requires trusted
component and advisory sources, remediation and release lineage, independent
review, and any separately authorized live validation that the case warrants.
Asset identity changes can appear as a missing old key and a new key; this
module does not infer identity continuity beyond the reconciled asset IDs.
