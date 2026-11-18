# Offline Emerging-Threat Applicability Review

This V9.4 increment turns caller-supplied advisory metadata and a caller-supplied
product inventory into a bounded review candidate list. It never ingests a
threat feed, exploit content, credentials, or target responses. It does not
contact a service, test a target, publish content, or authorize an emergency
run. The synthetic source fixture is
[`emerging-threat-review-v1.json`](../examples/emerging-threat-review-v1.json).

## Declared Sources

`build_emerging_threat_review` accepts an advisory, inventory, and whole-second
UTC review time. The advisory provides an opaque reference and an asserted
source digest, publication and expiration times, and sorted exact product and
version labels. A validation-content digest may be declared, but content
bytes are not accepted and that digest remains quarantined. The inventory
contains sorted opaque asset IDs, exact product and optional version labels,
and caller-declared scope and ownership states. The builder computes its own
content addresses for both complete source objects. It does not authenticate
the asserted advisory digest or the inventory's origin.
The maximum declared inventory age defaults to seven days and can be tightened
to any whole-second limit from one second to seven days. The report binds the
selected limit and the age computed from the caller-declared timestamp.

## Conservative Applicability

Only a declared in-scope asset with declared confirmed ownership and an exact
product and version match becomes a review candidate. An expired advisory,
stale inventory, out-of-scope asset, unknown scope or owner, unknown version,
different product, or different version receives a distinct disposition. The
exact expiration instant is expired. A different version is not proof of
safety because real advisories may contain ranges, exclusions, aliases, or
incomplete product data.
No version-range interpretation, CPE matching, exploitability assessment,
vulnerability confirmation, or live source freshness is claimed.

The closed report is described by
[`emerging-threat-review-v1.schema.json`](../registry/schemas/emerging-threat-review-v1.schema.json).
`verify_emerging_threat_review` reproduces the report from the separately
retained original sources.

## Signed Historical Opinion

`build_emerging_threat_review_statement` prepares an unsigned opinion over a
replayed report and its advisory and inventory digests. An external signer may
sign the domain-separated bytes from
`emerging_threat_review_statement_signing_bytes`. The verifier requires the
exact original sources, the pinned Ed25519 public key, and a claimed signing
time within seven days of the declared review time. The signature does not
establish when signing occurred. A changed source, reviewer
claim, disposition, signature, or key fails. The closed signed form is
[`emerging-threat-review-statement-v1.schema.json`](../registry/schemas/emerging-threat-review-statement-v1.schema.json).

The signature proves only possession of the pinned key over this historical
opinion. The claimed Independent Control or Independent Assurance role is not
authenticated against a production roster. `supports` is an opinion, not an
approval, action admission, content release, currentness assertion, or
qualification. Emergency priority never overrides authorization, containment,
or separation of duties. Threat-feed provenance, signed validation content,
real reviewer identity and independence, retention custody, and qualified
execution remain separate V9.4 requirements.
