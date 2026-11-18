# Advisory-to-asset applicability candidates

This repository-only V9.4 slice correlates a caller-supplied advisory with
caller-supplied installed-component observations and a reconciled asset
snapshot. It performs exact component reference and version matching only.
There is no version-range interpretation, threat-feed collection, exploit
attempt, remediation action, scheduling, or target authorization.

`verify_advisory_applicability_report_from_sources` recomputes a stored report
from its supplied advisory, reconciled asset snapshot, and component
observations. A valid self-hash alone does not prove that candidate states or
evidence coverage came from those sources. Replay rejects a false-negative
state and omitted supplied observations, while still making no claim that the
source feed itself is authenticated or complete.

Each advisory carries a source reference, source digest, publication time,
bounded exact affected component-version pairs, and a content digest. Each
component observation carries tenant and reconciled asset IDs, an exact
component-version pair, a unique source record reference, source digest,
observation and expiry times, and its own content digest. The correlator
requires a current-enough asset snapshot, exact tenant and asset membership,
and component observations no later than the asset snapshot. A repeated
source record with conflicting content is rejected.

The report labels each observed advisory component on an asset as:

- `candidate_match`: at least one current observed version is listed exactly
  by the advisory, with current asset provenance;
- `version_not_listed`: current component evidence exists, but none of its
  exact versions is listed;
- `stale_component_evidence`: the component evidence has expired; or
- `asset_identity_or_freshness_uncertain`: the reconciled asset has low
  confidence or no current provenance.

Assets without relevant component observations are listed separately as
missing component evidence. `version_not_listed` is not an unaffected verdict.
`candidate_match` is not proof of vulnerability or exploitability. Installed
software identity, backports, configuration, mitigations, and advisory quality
all require independent review. The output has no authority or qualification
effect.

This module validates content integrity and exact lineage only. It does not
authenticate advisory publishers or component inventory sources. Production
use still requires curated and verified intelligence, authenticated current
inventory, signed review, live action authority, qualified runners, and
delivery integration. Advisory correlation must never directly authorize a
target action.
