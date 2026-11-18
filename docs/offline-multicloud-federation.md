# Supplied multicloud federation trust projection

This R0 component belongs to profile `AOE-GC-D14-S09`, capability
`army.gc.d14.s09`, vector `AV-GC-D14-S09-01`, package
`IWP2-AOE-GC-D14-S09`, and wave `IW2-012`. Its component ID is
`cloud_supplied_multicloud_federation_projection`. It contributes partial
A7.4 evidence only and does not complete or qualify the specialist.

The schema version 1 model supplies finite exact trust declarations between
different AWS, Azure and GCP provider labels. Each trust names source and
target tenant labels, issuer, audience, subject and role labels, plus enabled
and completeness declarations. Each synthetic exchange references one trust,
declares its own exact labels, a supplied assertion-check disposition and a
supplied issuance outcome. There are no token bytes, secrets, endpoints or
provider API calls. Other providers and same-provider trusts are unsupported.

With complete trust, exchange and observation context, the projection expects
denial if the trust is disabled, the assertion is declared failed or an exact
field mismatches. Matching labels and a declared verified assertion do not
guarantee issuance because provider policy and token conditions are not
modeled, so that direction remains `unknown`. A supplied issued outcome
opposite an expected deny is a candidate declaration mismatch, not a verified
token issuance. Unknown assertion or incomplete
premises also produce `unknown` rather than a candidate. A declared verified label
does not verify cryptography.

`analyze_supplied_multicloud_federation` accepts a native model;
`analyze_supplied_multicloud_federation_bytes` accepts bounded ASCII JSON
bytes. `verify_supplied_multicloud_federation_analysis` rederives a report
against separately supplied original premises. `from_json` checks internal
derivation from the embedded source but cannot establish that the embedded
source is the approved original. Reports carry the exact source model,
domain-separated source and report addresses, bounds, false verification
flags, limitations and `none` effects. The synthetic R0 request is
`examples/offline-multicloud-federation-component.json`.

This leaf does not implement any provider policy language, token exchange,
cryptographic verification, transitive federation, cloud tenancy or role
assumption. It contacts no cloud provider, credential, network, process or
target, and establishes no live finding, authority, qualification or positive
use.
