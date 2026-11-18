# Restricted-asset inference

This repository-only V9.11 slice provides a lower evidence class when a
caller declares an asset restricted from exploitation. A case binds one
opaque asset, technique ID, restriction reason, curated-mapping source digest,
restriction source digest, and a closed set of prerequisite facets. Fresh
caller-supplied observations describe each prerequisite and one control facet.
The reviewer does not contact the asset or execute any technique.

If every prerequisite and the control facet has current supporting metadata,
the result is `bounded_inference_for_review` with low confidence. Missing or
unknown observations are insufficient; stale evidence is stale; current
contradictory evidence is counterevidence. A control observation marked
`contradicted_asserted` means a blocking control was asserted. A supported
control observation means only that the supplied control evidence did not
assert blocking. Neither establishes an exploitable path.

Every result is explicitly `restricted_asset_inference`, requires independent
review, and declares `successful_exploitation: false`. It is not a finding,
proof of a vulnerability, proof that a control was bypassed, an exception
signature, or target authority. Case metadata expires within 30 days and
observations within seven days. Conflicting facet evidence, cross-tenant or
cross-scope evidence, and future-dated records fail closed.

Production use still needs authenticated mapping provenance, verified current
asset and control evidence, restriction authority, independently signed
exceptions where warranted, and a report policy that keeps inference distinct
from live proof. The module validates record integrity and declared metadata,
not the truth or authenticity of the underlying observations.
