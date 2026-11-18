# Enterprise identity contracts

Phase 162 adds an infrastructure-independent enterprise identity boundary in
`sunderkey.enterprise_identity_contracts`. The module defines deterministic
records and decisions for role-based access control, already-verified SSO
claims, and SCIM-style provisioning commands. It does not contact an identity
provider, parse or verify an identity-provider token, alter a directory, grant
authority, revoke a session, or make a network request.

## Security boundary

Every record is an immutable frozen value with a type discriminator, schema
version, derived record ID, SHA-256 content address, and explicit effects map.
All effects are `none`. Canonical JSON is printable ASCII with sorted keys and
no insignificant whitespace.

Tenant identity is repeated on policies, roles, bindings, SSO claims,
authorization requests, decisions, and provisioning commands. Cross-tenant
composition or resource access is rejected. Text fields have strict length and
character limits and reject common private-key, credential, bearer-token,
session-token, and embedded-credential patterns. Evidence and attributes are
represented by content digests rather than raw values.

## Deny-by-default authorization

`EnterpriseIdentityPolicy` requires `default_decision` to be `deny` and uses a
closed permission vocabulary. `authorize` allows a request only when all of
the following are true:

1. The subject, resource, binding, and policy have the same tenant.
2. Exactly one binding exists for the subject.
3. The binding is active and valid at the request time.
4. Every referenced role exists in the policy.
5. The combined roles comply with all duty constraints.
6. The effective permissions include the requested permission.

Any missing input, ambiguity, unknown role, invalid status, stale binding,
tenant mismatch, or absent permission produces a typed deny decision. The
decision documents effective permissions, reason codes, source hash, policy
hash, and evaluation time, but it does not grant authority by itself.

## Separation of duty

The policy must include at least these symmetric constraints:

- Mission approval is separate from mission execution.
- independent Control review is separate from independent Assurance review.
- Evidence custody is separate from findings review.

The model rejects a role that contains both sides of a required constraint. It
also rejects a role binding whose combined roles violate a constraint. This
prevents a subject from bypassing separation by accumulating individually
valid roles.

## SSO claim admission

`VerifiedSsoAssertion` is an intake format for claims that a separate trusted
component has already verified. It has no token, signature, certificate,
cookie, header, or credential-value field. An assertion binds:

- tenant, issuer, audience, and subject
- authentication, issue, and expiry times
- MFA presence and assurance context
- session identifier
- SHA-256 verification evidence
- the fixed `externally_verified: true` declaration

`admit_sso_assertion` compares these claims with a tenant trust policy. It
checks issuer, audience, assurance, MFA, clock skew, authentication age,
expiry, and maximum session duration. The result is an immutable allow or deny
decision. Signature verification and identity-provider connectivity remain
outside this module and require a separately authorized adapter.

## SCIM-style provisioning commands

`ProvisioningCommand` describes create, update, deactivate, tombstone,
membership, and session-revocation intent without applying it. Every command
binds a tenant, actor, resource type, stable internal resource ID, external ID,
idempotency key, expected version, next version, issue time, optional current
resource hash, attribute digests, and any membership or session references.

Create commands require version zero and no precondition. All other commands
require a SHA-256 precondition and exactly increment the expected version.
Membership operations require a membership resource and member subject.
Session revocation requires a user resource and bounded session ID list.

`validate_provisioning_command` checks tenant isolation, actor identity,
active identity-administrator authority, resource existence, optimistic
versioning, content preconditions, and idempotency. Reusing an idempotency key
for different content is denied. Exact command replay is reported as a
duplicate and is not applied again.

Deactivate, tombstone, and membership removal commands declare themselves as
deprovisioning. Every deprovisioning decision sets
`session_revocation_required` so downstream infrastructure cannot silently
omit session invalidation. Tombstone commands separately declare
`tombstone_required`. These declarations are obligations only. This module
never changes directory or session state.

## Schema and integration

`registry/schemas/enterprise-identity-contract-v1.schema.json` validates the
complete `EnterpriseIdentityContract`. Every object is closed with
`additionalProperties: false`, and arrays have explicit limits. Python
validation additionally enforces tenant equality, content addresses,
required duty constraints, combined-role conflicts, time ordering, command
shape, version progression, and decision semantics.

Persisting these records, validating live federation tokens, calling a SCIM
endpoint, synchronizing an external directory, and revoking real sessions are
future adapter responsibilities. Those capabilities require infrastructure,
credentials, trust configuration, audit storage, and explicit authorization.
