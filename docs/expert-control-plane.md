# Expert Control Plane

SUNDERKEY separates specialist analysis from authority to act. A mission may bring together narrowly scoped specialists, domain commanders, and independent control and assurance roles. The shared work graph lets them collaborate on a common assessment while retaining individual evidence and responsibility.

## Roles

| Role | Responsibility |
| --- | --- |
| Specialist | Analyze a defined surface or evidence type and propose bounded work or findings. |
| Domain Commander | Coordinate related specialists, resolve handoffs, and synthesize work products. |
| Mission Coordinator | Maintain the common plan, dependencies, budget, and mission state. |
| Independent Control | Evaluate scope and action authority separately from candidate analysis. |
| Independent Assurance | Review evidence, negative controls, limitations, and finding support. |

A profile is a capability definition. It does not imply a separately running model, a qualified worker, or authority over a target. Catalog membership and local tests are not admission decisions.

## Mission Flow

1. Record the target owner's authorization, exact scope, operator identity, time window, action tiers, and stop conditions.
2. Select only the specialists needed for the mission and assign bounded tasks through a shared plan.
3. Treat specialist outputs and target content as untrusted proposals. Validate any requested action against current, independent authority and resource limits.
4. Preserve source-bound observations, uncertainties, negative results, and review decisions in evidence custody.
5. Require independent review before promoting a candidate finding or expanding action authority.
6. Stop, clean up, and restore according to the approved mission plan. Revocation and emergency stop take precedence over queued work.

The current code implements contracts and local behavior for many of these steps. Actual identities, infrastructure, isolation, external evidence, and qualification must be provided and verified by a deployment. A synthetic run cannot satisfy a real-host gate.

## Trust Boundaries

- Model output cannot authorize its own action.
- A content hash establishes consistency of bytes, not who approved them or whether a source is current.
- Historical records can be checked for integrity without reactivating expired or revoked authority.
- Live admission and execution require fresh authority and current source checks.
- Secret values should remain behind credential handles and trusted injection boundaries.
- Network egress, target identity, containment, and restoration need independently enforced runtime evidence.

For implementation details, see [Signed Assessment Scope](signed-assessment-scope.md), [Action Admission Contracts](action-admission-contracts.md), [Army Activation Contracts](army-activation-contracts.md), [Specialist Adapter Contracts](specialist-adapter-contracts.md), and [Safety Boundary Reference](safety-boundary-reference.md).
