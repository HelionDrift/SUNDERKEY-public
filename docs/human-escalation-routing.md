# Human-review escalation routing proposals

This repository-only V9.14 slice produces deterministic reviewer proposals for
caller-supplied review cases and roster entries. It does not authenticate
reviewers, verify qualifications, assign work, grant evidence access, send a
notification, make a review decision, or authorize a target action.

Cases bind a tenant, scope digest, evidence digest, originating principal and
team, expertise tags, required reviewer roles, priority, and response deadline.
Roster entries carry a tenant, reviewer and team references, caller-asserted
role capabilities and expertise, case conflicts, availability, capacity, and
source digest. All records and the routing plan are content-addressed. The
planner accepts at most 256 cases and 1,024 reviewers per plan.

For each case, the planner excludes the originating principal, conflicting
reviewers, unavailable or full reviewers, reviewers lacking every required
expertise tag, and cross-tenant entries. Independent Control and Assurance
roles must come from a team other than the originating team. One person cannot
fill two roles on the same case. A deterministic maximum matching fills the
largest feasible set of distinct reviewers before leaving slots unfilled.
Cases are considered by priority and response deadline, with capacity carried
through the batch. An expired case has only `deadline_expired` slots.

A `proposed` slot is not an assignment or attestation. `unfilled` remains
explicit when the supplied roster cannot satisfy a role. The plan does not
persist active load across invocations, so the caller must provide current,
trusted capacity and conflict data. Production operation still requires
verified human identities and qualifications, signed roster custody,
authenticated assignment acceptance, secure evidence access, notification,
independent dispositions, and durable load accounting. Human review cannot
retroactively authorize a prior target action.
