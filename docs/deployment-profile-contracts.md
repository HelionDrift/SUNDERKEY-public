# Deployment profile and restricted worker contracts

This increment defines the repository-only contract boundary for roadmap
packages S6.6 and D8.7. It describes how a SUNDERKEY worker may be packaged,
constrained, admitted, stopped, cleaned up, restored, and required to export
evidence. It does not deploy a worker or make any live environment suitable for
operation.

The Python module is `sunderkey.deployment_profile_contracts`. The strict JSON
schema is
`registry/schemas/deployment-profile-contract-v1.schema.json`.

## Supported deployment profiles

The contract has deterministic baselines for five deployment topologies:

| Profile | Ingress | Egress | Update channel |
| --- | --- | --- | --- |
| Managed service | Managed control plane | Restricted allowlist | Managed signed channel |
| Customer-hosted worker | Mutual TLS control plane | Customer proxy | Customer signed mirror |
| Private cloud | Private control plane | Private allowlist | Private signed mirror |
| Restricted network | Customer relay | Customer relay | Relayed signed bundle |
| Disconnected operation | Signed removable media | Evidence removable media | Offline signed bundle |

The topology and network claims are inseparable. A profile cannot label itself
as disconnected while claiming control-plane ingress, online updates, or
online credential delivery. Connected profiles cannot claim an offline
validity window.

These records describe requirements. They do not create mutual TLS identities,
network routes, proxies, relays, removable media, or update systems.

## Immutable trust and runtime bounds

Every profile is immutable and content addressed. It requires:

- public trust-root references and public-material digests for mission bundles,
  revocation snapshots, update bundles, and evidence exports;
- exact component versions and artifact digests, with moving aliases rejected;
- an explicit capability set and tool allowlist;
- one or more permitted reference-only credential delivery modes;
- encrypted evidence custody and a required signed export manifest;
- bounded stop acknowledgement, cleanup, and restoration contracts;
- a maximum worker clock skew; and
- for disconnected operation only, a bounded offline validity period.

Trust references never contain private key material. The module does not create
or validate cryptographic signatures. Operational signature verification must
be supplied by a separately reviewed deployment integration.

## Signed mission and revocation inputs

An admission request binds the exact deployment profile to caller-supplied
references for:

- a signed mission bundle with tenant, assessment, signed scope, issue time,
  expiry time, content digest, signature reference, and signing trust root;
- a signed revocation snapshot with capture time and expiry time;
- a signed evidence export manifest bound to the required evidence store;
- requested capabilities and tools;
- the credential delivery mode and lease bound; and
- the worker clock and last-online time.

The records are reference-only. Mission instructions, credential values,
private keys, tokens, cookies, and other raw secrets are forbidden.

## Fail-closed admission

`evaluate_deployment_admission` performs deterministic contract evaluation. It
denies requests when it finds any of the following conditions:

- profile identity or digest mismatch;
- unpinned or incorrectly purposed trust roots;
- expired or not-yet-valid mission bundles or revocation snapshots;
- disconnected bundles or snapshots that exceed the offline window;
- worker clock skew outside the profile bound;
- unsupported capabilities or tools outside the allowlist;
- forbidden credential delivery or an excessive credential lease;
- evidence export manifest, trust root, or store mismatch; or
- contradictory time metadata.

A request that passes these checks is only
`contract_compatible_unverified`. Its result always retains the
`live_deployment_verification_required` blocker. The contract therefore cannot
authorize deployment, target action, or qualification.

## Stop, cleanup, restoration, and custody

A valid profile must support all of the following:

1. A bounded fail-closed stop acknowledgement.
2. Cleanup verification after work ends or is interrupted.
3. Restoration verification for any changed target state.
4. Encrypted evidence custody while evidence is held by the worker.
5. Signed manifest export to the named evidence store.
6. Local deletion only after export verification.

Profiles that cannot stop or export evidence are rejected at construction. A
runtime implementation must later prove those controls under interruption,
clock drift, revocation, partial connectivity, and failed export conditions.

## Explicit non-effects

Every top-level record declares the following effects as `none`:

- authorization;
- credential access;
- deployment;
- filesystem mutation;
- network access;
- qualification;
- signature generation; and
- target action.

The module contains no deployment, network, database, process, filesystem,
credential, signing, or provider clients. Production readiness still requires
live infrastructure, dedicated operational identities, cryptographic trust
material, transport enforcement, durable custody, worker isolation,
observability, emergency-stop tests, cleanup and restoration exercises, and
independent operational review.
