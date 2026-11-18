# Supplied Entra app-role claim review

The `AOE-GC-D11-S14` partial specialist compares caller-supplied active,
direct app-role assignment labels with caller-supplied opaque role-claim
labels for the same subject and resource. It lists claimed roles without a
matching supplied direct assignment, active assigned roles absent from a
supplied claim, and a declared tenant mismatch. It withholds role comparison
when tenant labels differ. These are structural review signals, not token or
authorization verdicts.

The exact native JSON model declares `schema_version: 1`,
`semantics_profile: supplied-entra-direct-role-claim-review-v1`, an opaque
tenant reference, up to 256 direct assignments, and one to 128 opaque token
observations with at most 16 role references each. Each assignment is keyed
by a unique ID and subject, resource, and role tuple. Each observation has a
unique opaque token reference, declared tenant, subject, resource, and role
list. No token bytes or reusable credentials are accepted. Inputs and reports
are bounded. The typed report can be replayed against current supplied input.

Microsoft documents [app-role assignments](https://learn.microsoft.com/en-us/graph/api/resources/approleassignment)
and [optional-claim configuration](https://learn.microsoft.com/en-us/entra/identity-platform/optional-claims)
as distinct sources, with claim-emission exceptions. This model does not
infer group assignment, token issuance chronology, claim customization,
signature validity, or app authorization. All tenant, assignment, and claim
labels are caller assertions. A mismatch does not prove a bad token,
misconfiguration, or effective access. No identity provider, credential,
service, network, or target is contacted. The component grants no action
authority or qualification. The [synthetic example](../examples/offline-entra-role-claim-component.json)
uses only fictitious opaque references.
