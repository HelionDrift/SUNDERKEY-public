# Supplied Hybrid Identity Mappings

The `AOE-GC-D11-S17` partial specialist, component
`supplied_hybrid_identity_mappings`, compares caller-supplied AD Connect-shaped
sync mappings and AD FS-shaped federation-route declarations with a
caller-supplied local policy. It identifies reused source or target anchor
references across enabled mappings when uniqueness is required, and enabled
routes whose issuer reference is absent from the supplied allowlist. These are
declaration mismatches, not validation of a token, claim, trust, or effective
identity path.

The exact native JSON model has `schema_version: 1`, a bounded `source_id`,
`inventory_complete`, `policy`, up to 64 `sync_mappings`, and up to 64
`federation_routes`; at least one declaration is required. Anchor, issuer,
and relying-party references are opaque SHA-256 references. A complete model
with only disabled declarations returns `no_applicable_supplied_declarations`,
not a positive match. Incomplete inventory yields `unknown`, no candidates,
and one unknown row per declaration. Replay verification recomputes the report
from the separately supplied original model.

The component does not acquire or validate tokens, claims, signing keys, or
credentials; contact an identity provider, network, or target; publish a
finding; or grant qualification. The
[synthetic example](../examples/offline-hybrid-identity-mappings-component.json)
uses fictitious digest references only.
