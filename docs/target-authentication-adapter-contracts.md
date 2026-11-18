# Target authentication adapter contracts

## Purpose and boundary

Phase 183 defines the version 2 contract boundary between SUNDERKEY's existing
scope, credential, execution-control, and target-session records and a future
target authentication adapter. The version 2 records describe what an adapter
would be permitted to receive, what it must attest, and how its evidence is
verified. They do not resolve a credential, contact an identity provider, open
a browser, create a network connection, authenticate to a target, answer a
challenge, create a remote session, or perform cleanup.

The design is additive. Existing version 1 authenticated-target, credential
broker, assessment transport, and authorized target-session records retain
their current meanings. A version 2 record binds those records by identity and
content hash. It does not upgrade a version 1 record in place and it does not
turn a repository-only contract into an execution path.

`NO_EFFECTS` fixes browser automation, credential resolution, lifecycle action,
MFA response, network access, provider invocation, remote authentication, and
session mutation to `none`. `NO_CLAIMS` separately fixes authorization,
deployment, live readiness, parity, qualification, successful authentication,
and superiority to `none`. Every top-level record serializes both maps exactly.

No Phase 183 artifact is evidence of live execution, qualification, parity,
superiority, production readiness, authority, deployment, or successful
authentication.

## Additive version 2 architecture

The public surface has seven top-level content-addressed records and one nested
content-addressed profile:

1. `TargetAuthenticationProviderBinding` binds a provider, an instance, an
   exact implementation and version, artifact and configuration digests, an
   execution environment, an environment attestation digest, and the immutable
   profiles and operations that instance declares it supports, inside a
   bounded issuance and expiry window.
2. `TargetCredentialProvenance` binds one version 1 credential descriptor and
   lease to one principal and one required factor, provider binding, lease
   window, lease use, source reference, transport-reference digest, and mapping
   attestation.
3. `TargetAuthenticationPolicy` binds one tenant, mission, signed scope,
   target, provider, mode, profile, exact version 1 target-session evidence,
   provenance set, lifecycle-obligation set, one attempt, and time window.
4. `TargetAuthenticationCommand` binds the exact policy, provider, execution
   environment, operation, mode, profile, version 1 evidence, provenance set,
   lifecycle obligations, session references, and optional fixture scenario.
5. `TargetAuthenticationFlowEvidence` binds one ordered observed stage to the
   exact command, provider, execution environment, input digest, optional
   output digest, attestations when required, time, and optional closed failure
   code.
6. `TargetAuthenticationResult` binds the command, provider, environment,
   complete flow-evidence binding set, outcome, failure code, optional session
   evidence, lifecycle disposition, attestations when required, and completion
   time.
7. `TargetAuthenticationReceipt` binds the verified provider, policy, command,
   result, flow evidence, execution environment, lifecycle-complete flag, and
   issue time.

`AuthenticationProfileEvidence` is the nested TAPE content address carried in
provider, policy, and command records. `ContentAddressBinding` always carries
both a record identifier and its SHA-256 content hash. The verifier is a pure
evidence checker. It reconstructs identities, checks all relationships, and
never invokes the provider named by the records.

## Credential reference provenance

The existing repository has two deliberately opaque credential reference
forms. Credential broker descriptors use `credentialref:`. Runtime command
boundaries use `credref:`. Version 2 makes any relationship between them
explicit instead of assuming that matching suffixes, names, or digests mean
the references identify the same credential.

A `TargetCredentialProvenance` record must bind:

- the exact provider record identifier and content hash;
- the principal reference;
- one exact authentication factor from the selected profile;
- the exact version 1 `CBD-` credential descriptor identifier and content hash;
- the exact version 1 `CLZ-` credential lease identifier and content hash;
- the lease mode, issuance time, expiry time, and bounded use number;
- the descriptor's source `credentialref:` value;
- the runtime `credref:` value by SHA-256 digest only;
- the mapping attestation digest; and
- a creation time inside the lease window.

The runtime form is not derived from the descriptor form by string rewriting.
Only the exact content-addressed provenance and mapping-attestation digest may
associate the two. The verifier rejects a missing provenance record, a
namespace mismatch, an unbound descriptor or lease address, a changed
runtime-reference digest, a provider substitution, a command outside the
lease window, an invalid one-time lease use number, or an invalid principal
count for the selected topology.

The chain requires exactly one provenance record for each required factor for
each principal. A principal cannot have duplicate provenance for one factor,
omit a profile factor, or add a factor outside the profile. A non-multi
topology has exactly one principal. A multi-principal topology has at least two
distinct principals, each with the complete factor set. Policy and command
cardinality therefore equals principal count multiplied by required factor
count.

The provenance record retains the descriptor and lease identities and hashes.
It retains only a digest for the runtime `credref:` value. Raw credential
material is never serialized. User passwords, authorization values, cookies,
private keys, bearer tokens, one-time codes, recovery codes, magic-link values,
and the transport `credref:` value itself have no serialized field.

## Provider binding

Provider selection is an exact security binding, not an informational label.
`TargetAuthenticationProviderBinding` names one `providerref:` and one
`instanceref:`, an implementation name, an exact implementation version, an
artifact digest, a configuration digest, an execution environment, an
environment-attestation digest, and one or more supported TAPE profiles.
It also declares one or more supported operations from `acquire_session`,
`refresh_session`, and `terminate_session`, plus a bounded issuance and expiry
window. Malformed names or versions, duplicate profiles, unsupported profiles
or operations, omitted hashes, and work outside the provider window are
invalid.

The policy and command carry the provider record identifier and content hash.
Every flow observation and result repeats the same provider binding. The chain
verifier rejects a provider, instance, implementation, environment, profile,
or content-address substitution. The environment-attestation digest on the
provider binding identifies supplied evidence. It does not prove deployment,
qualification, isolation, trustworthiness, or target authority.

## Normalized authentication profile

Each policy and command selects one `AuthenticationProfileEvidence` value from
the immutable `AUTHENTICATION_MODE_PROFILES` matrix. Its dimensions are mode,
protocol, factor set, session carrier, principal topology, required successful
flow-stage set, and lifecycle-obligation set. The TAPE identifier and digest
are derived from all seven dimensions.

The closed values are:

- modes: `basic_reference`, `bearer_reference`, `form_login_password`,
  `form_login_totp`, `form_login_email_otp`, `magic_link_reference`,
  `oauth2_pkce`, and `oidc_pkce`;
- protocols: `http_basic`, `http_bearer`, `html_form`, `magic_link`, `oauth2`,
  and `oidc`;
- factors: `password_reference`, `bearer_reference`, `totp_reference`,
  `email_otp_reference`, `magic_link_reference`,
  `federated_identity_session_reference`, and `pkce_verifier_reference`;
- carriers: `authorization_header_reference`,
  `browser_cookie_jar_reference`, `browser_redirect_callback_reference`, and
  `magic_link_callback_reference`; and
- topologies: `single_principal`, `multi_principal`, and
  `federated_principal`.

Multi-principal is a topology, not an authentication mode. Every mode has one
multi-principal profile. Basic, bearer, form-password, form-TOTP, form-email-OTP,
and magic-link modes also have a single-principal profile. OAuth 2.0 with PKCE
and OIDC with PKCE are separate, explicit modes and protocols. Each has a
federated-principal profile and a multi-principal profile. Both require a
federated identity session reference and a PKCE verifier reference, and both
use a browser redirect callback carrier. The immutable matrix therefore has 16
exact profiles. An unsupported mode and topology pair or any altered nested
profile fails closed.

Profiles describe evidence requirements. They do not implement any protocol,
factor, carrier, topology, redirect, or challenge response.

## Profile-specific flow evidence

Generic success text is insufficient. A flow consists of one or more
`TargetAuthenticationFlowEvidence` records with contiguous sequence numbers
and nondecreasing observation times inside the command window. Each record
binds an input digest, an optional output digest, and exactly one closed stage.
An authenticated result must include every successful stage required by its
selected TAPE profile:

| Mode and topology | Required successful stages |
| --- | --- |
| Basic or bearer, single or multi-principal | `credential_reference_bound`, `session_observed` |
| Form password, single or multi-principal | `credential_reference_bound`, `session_observed` |
| Form TOTP, single or multi-principal | `credential_reference_bound`, `challenge_observed`, `session_observed` |
| Form email OTP, single or multi-principal | `credential_reference_bound`, `challenge_observed`, `session_observed` |
| Magic link, single or multi-principal | `credential_reference_bound`, `callback_observed`, `session_observed` |
| OAuth 2.0 PKCE, federated or multi-principal | `credential_reference_bound`, `redirect_observed`, `callback_observed`, `session_observed` |
| OIDC PKCE, federated or multi-principal | `credential_reference_bound`, `redirect_observed`, `callback_observed`, `session_observed` |

An authenticated flow starts with `credential_reference_bound`, contains the
profile's required stages in their declared order, ends with
`session_observed`, and contains no failure stage. A failed or stopped flow
ends with `failure_observed` and the same closed failure code as the result. A
terminated flow ends with `termination_observed`. Missing or out-of-order
required stages, duplicate or noncontiguous sequence numbers, invalid times,
unbound content addresses, and unknown stage values are invalid. The policy
fixes `maximum_attempts` to the exact native integer one. Booleans, floats,
integer subclasses, and coercible strings are rejected before policy identity
hashing. The checked-in policy schema also fixes its integer ceiling to one.
Valid integer-one policy and receipt identities are unchanged; this does not
add an attempt, retry, runtime effect, or target authority.

## Fixture and external execution classes

Version 2 separates deterministic repository fixtures from externally supplied
adapter evidence:

- `deterministic_fixture` means the result came from an in-process test double
  over synthetic inputs. It may prove parser, binding, state-machine, and
  failure-path behavior. It cannot prove a target interaction or provider
  deployment. Its command requires exactly one `fixtureref:` scenario. Its
  flow and result records require provider and environment runtime-attestation
  fields to be null.
- `external_runtime_observation` means supplied evidence claims an observation
  from an externally implemented boundary. Its command forbids a fixture
  scenario. Every flow record and the result require distinct provider and
  environment attestation digests. Repository verification can validate their
  structure and binding only. It cannot establish that the external event
  occurred or was authorized.

The provider binding fixes the execution environment and the command must
repeat it. A fixture result cannot satisfy an external-runtime-observation
requirement. An external observation cannot be imported as a fixture to avoid
its attestation obligations. The provider, command, every flow record, result,
and receipt must carry the same execution environment. For external evidence,
each flow environment attestation and the result environment attestation must
equal the provider binding's environment attestation. The result provider
attestation must equal the final flow record's provider attestation.

## Closed failures and terminal states

Failure is represented through `AuthenticationFailureCode`, a closed set of 17
values:

- `command_expired`
- `credential_reference_unavailable`
- `credential_provenance_mismatch`
- `provider_identity_mismatch`
- `policy_binding_mismatch`
- `unsupported_mode`
- `challenge_not_satisfied`
- `callback_invalid`
- `session_not_established`
- `session_refresh_failed`
- `session_termination_failed`
- `fixture_scenario_invalid`
- `provider_unavailable`
- `timeout`
- `operator_stop`
- `mission_stop`
- `evidence_incomplete`

The closed outcomes are `authenticated`, `terminated`, `failed`, and
`stopped`. Failed and stopped results require one failure code and cannot bind
a resulting session. Stopped results accept only `operator_stop` or
`mission_stop`. Authenticated results require both a resulting session
reference and session-evidence digest. Terminated results retain neither.
Successful results cannot carry a failure code. Unknown codes, outcomes, and
free-text exception details are invalid.

## Lifecycle obligations

An accepted result is not automatically the end of the target-session
lifecycle. The closed obligations are `secret_non_persistence`,
`session_isolation`, `refresh_predecessor_bound`, `logout_required`,
`revocation_observation_required`, and `mfa_operator_bound`.

The immutable profile supplies its base obligations. Form TOTP adds
`mfa_operator_bound`, as does form email OTP. A refresh command adds
`refresh_predecessor_bound`, requires session-bound leases, and must name
distinct predecessor and requested sessions. An acquire command must name a
requested session and no predecessor. A terminate command must name a
predecessor and no requested session.

The result partitions the command's obligations into disjoint satisfied and
pending sets. The verifier requires their union to equal the command set. The
receipt sets `lifecycle_complete` only when the pending set is empty. This flag
records contract-chain evidence only. It does not perform logout, revocation,
browser teardown, cookie removal, remote cleanup, or lifecycle storage. An
authenticated result must keep exactly `logout_required` and
`revocation_observation_required` pending and must mark every other obligation
satisfied. Its receipt therefore cannot claim lifecycle completion. A
terminated result cannot retain any pending obligation and its verified
receipt records lifecycle completion. These rules authenticate the record
chain only. They do not authenticate an operator or prove the underlying
external lifecycle actions.

## Exact version 1 evidence binding

`V1TargetSessionEvidenceBinding` is the bridge to the existing execution and
authorized target-session boundaries. It contains exact typed identifiers and
hashes:

- `ECP-` execution policy identifier and SHA-256 content hash;
- target-session intent SHA-256 content hash;
- `ECRQ-` execution request identifier and SHA-256 content hash;
- `ECAR-` admission receipt identifier and SHA-256 content hash;
- `ATSP-` authorized target-session runtime policy identifier and SHA-256
  content hash; and
- `ASR-` authorized target-session runtime receipt identifier and SHA-256
  content hash.

The policy and command must carry identical values for this complete nested
object. Omitting one field, binding only an identifier, binding only a hash,
or substituting any version 1 evidence fails verification. Phase 183 checks
the supplied content addresses and equality relationship. It does not
reinterpret the underlying version 1 records or convert their contract-only
evidence into proof of live authentication.

## Content addressing and canonical encoding

Provider bindings, credential provenance records, profiles, policies,
commands, flow evidence, results, and receipts use canonical printable ASCII
JSON and SHA-256 content addresses. Their identifiers are derived from a
record-kind domain and canonical body. Declared identifiers and hashes are
always recomputed during parsing and verification.

Strict parsing rejects duplicate JSON keys, unknown fields, non-canonical
encoding, non-finite numbers, booleans where integers are required, ASCII
control characters, unsupported reference namespaces, unbounded collections,
malformed versions, secret-like material, and broken content addresses.
Set-like fields are normalized, sorted, and required to be unique.

Every cross-record relationship binds both identifier and content hash. An
identifier alone is not sufficient. A verifier never trusts a declared hash
without recomputing it.

## Verification behavior

Verification proceeds in fail-closed order:

1. Strictly parse each record and recompute its content address.
2. Confirm supported schema and contract versions.
3. Verify policy scope, nested provider and policy windows, provider instance,
   implementation, environment, supported profile, supported operation, and
   execution-class constraints.
4. Verify credential descriptor and lease addresses, runtime-reference
   provenance, provider binding, exact per-principal factor coverage, distinct
   principal count, use number, lease mode, and command containment inside
   every lease window.
5. Verify the normalized profile and its compatibility matrix entry.
6. Verify that policy and command carry the identical complete version 1
   ECP execution-policy, intent, ECRQ execution-request, ECAR
   admission-receipt, ATSP runtime-policy, and ASR runtime-receipt binding.
7. Verify that the result repeats the exact command and provider bindings.
8. Verify the ordered profile-specific stages, evidence hashes, environment
   attestations, timestamps, session state, and one-attempt ceiling.
9. Verify terminal-state, failure-code, cleanup, revocation, and lifecycle
   invariants.
10. Recompute the receipt identity and hash.

Any failed step stops acceptance. Verification does not retry, perform network
discovery, resolve an opaque reference, fetch missing evidence, infer a
provider, substitute defaults, or repair a record.

The seven record-specific parsers and `parse_target_authentication_record`
perform canonical reconstruction. `verify_target_authentication_chain` checks
the complete relationship without producing effects.
`issue_target_authentication_receipt` issues a receipt only after that chain
passes, then verifies the resulting receipt against the same chain.

## Compatibility rules

Version 2 is compatible with existing records only through explicit bindings:

- A version 1 credential descriptor and lease remain version 1. Their exact
  identities and hashes are referenced by version 2 provenance. Policy and
  command records bind the complete provenance records by identifier and hash.
- A version 1 `credentialref:` and a runtime `credref:` are distinct values.
  Neither is accepted in the other's field.
- Existing authenticated-target evidence remains valid for its stated version
  and effects. Version 2 may bind it but does not reinterpret its protocol or
  session claims.
- Existing authorized target-session receipts remain valid. They do not imply
  that a version 2 provider profile, provenance record, or external runtime
  observation was present.
- A version 2 receipt is never down-converted to version 1. Consumers that do
  not recognize version 2 must reject it or preserve it as opaque evidence.
- Unknown enum values, fields, profile combinations, failure codes, and record
  kinds fail closed. Forward compatibility requires a new schema or contract
  version and an explicit migration rule.

This preserves existing callers while allowing a separately reviewed adapter
implementation to adopt the stronger boundary later.

## Claim boundaries

Phase 183 can establish that the repository defines deterministic and strict
contracts for credential provenance, provider identity, authentication
profiles, flow evidence, result classification, lifecycle obligations, and
receipt verification. Deterministic tests may establish that those contracts
reject substitution, replay, ambiguity, malformed evidence, and incompatible
profiles under their fixtures.

Phase 183 cannot establish that any external runtime implementation exists,
that any identity provider or target accepted an authentication attempt, that
any credential was resolved safely, that a remote session was created or
removed, or that an operator, provider, network, host, vault, browser, or
target is qualified. Repository receipt validity is not proof of the truth of
an external attestation.

## Remaining INF-003 infrastructure

Resolving the repository contract portion of INF-003 still leaves the
following deployment work external:

- an approved secret broker or vault and a provider-specific reference
  translator that emits independently reviewable provenance evidence;
- provider adapters pinned to exact artifacts and configurations for each
  supported protocol, factor, carrier, and topology;
- isolated HTTP and browser workers, redirect receivers, MFA operator
  interfaces, and identity-provider integrations;
- durable atomic lease-use, replay, session, cookie, cleanup, revocation, and
  lifecycle stores;
- authenticated clocks, safety monitors, cancellation and emergency-stop
  propagation, egress enforcement, target authorization, and scope checks at
  the deployment boundary;
- tenant isolation, log redaction, evidence custody, retention, deletion,
  monitoring, backup, and recovery;
- negative-path, timeout, partial-effect, cleanup, revocation, concurrency,
  and provider-substitution evidence from the selected environment; and
- independent review, qualification, change control, and explicit deployment
  authority for each provider and environment.

Until those components and decisions exist, the repository provides only
deterministic fixture evidence construction and verification. External runtime
observation contract support must remain distinguished from live, qualified,
or production operation.
