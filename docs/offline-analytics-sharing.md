# Supplied managed-analytics sharing

The `AOE-GB-D07-S12` partial specialist compares caller-declared dashboard
shares with opaque principal, workspace, and data-source tenant labels. It
separates `view` and `export` declarations, reports granted cross-tenant
workspace or source labels, and keeps denied, unknown, or missing shares
distinct. A missing share remains unknown when the caller marks the sharing
declarations incomplete.

The exact native JSON model declares `schema_version: 1`,
`semantics_profile: supplied-analytics-sharing-v1`, a completeness boolean,
up to 128 principals, 64 workspaces, 128 sources, 128 dashboards, 256 shares,
and 16 objectives. Each dashboard names up to 32 unique declared sources.
Principal, tenant, workspace, source, and dashboard identities use opaque
digest references. Duplicate or contradictory share declarations are refused.
Input structure and output size are bounded, and the typed report replays
against the original model.

These assertions do not authenticate identity, effective sharing, dashboard
configuration, query permissions, row policy, source contents, rendering, or
export. A declared cross-tenant share is a review hypothesis, not an exposure
finding. No analytics service, provider, credential, network, or target is
contacted, and no action authority or qualification is granted. The
[synthetic example](../examples/offline-analytics-sharing-component.json)
uses only fictitious opaque references.
