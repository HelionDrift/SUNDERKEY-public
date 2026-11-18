# Local historical repository authentication inspection

The shared `read_provider_evidence_repository_ingest_authentication(store,
registry, authentication_id)` reader and the stdout-only
`provider-evidence-repository-authentication-show` command inspect one exact
schema-39 ERI record. They return original authentication-report provenance,
not evidence bytes, current permission or independent provider-control evidence.

The reader does not require a repository identity, signed read assertion,
credential or live clock. Existing service `get` delegates to that same reader.
It does not instantiate the positive-publication service or accept unsigned JSON
as a substitute for stored signature and source verification.

## Explicit local command

Supply an existing local MissionStore, its exact registry and the original ERI
identity recorded by the metadata service. For example, in Git Bash:

```sh
export PYTHONPATH="src"
python -m sunderkey.cli provider-evidence-repository-authentication-show \
  --store /path/to/existing-mission-store.sqlite3 \
  --registry registry/army-v2.json \
  --authentication-id "$authentication_id"
```

Set `authentication_id` to the actual stored ERI before running the command.
An OpenAI smoke or pack receipt identity is a different record family and is
not an ERI. This command does not create sample custody or discover a latest ID.

The three options are required. There is no output-path, initialization,
migration, latest-selection, credential, signing or expected-identity option.
Successful output contains `verification_scope: historical_custody_only`,
`current_authority_verified: false` and the verified historical commit receipt.
The receipt's existing provider-report-only, unverified-control and
nonqualifying statuses remain unchanged. Validation and receipt serialization
finish before any success output is written to stdout.

## Verification and transaction boundary

The reader rejects non-native or malformed ERI identities before opening a read
connection. One transaction selects the exact row, requires schema 39, validates
bounded raw canonical JSON and projected columns, verifies its historical mission
and principal ledger, replays exact source custody and reconciles the original
repository assertion use and protected effect. Reciprocal orphan checks remain
part of that mission's historical verification; lookup is not merely a selected
row's content-hash comparison.

The connection-local `query_only` flag is set and checked before custody reads.
It prevents SQL writes on that reader connection and does not change later
ordinary writer connections. The existing MissionStore connection still opens
an existing file in `mode=rw`; this is not a new OS-level read-only handle or a
guarantee of zero filesystem activity. No application state is created,
migrated, published or renewed by inspection.

History remains readable after the original assertion or scope expires, after
revocation or trust-policy rotation, and after mission stop. That availability
does not permit new publication or replay-for-use: the positive API still needs
its live-currentness, mission-state and local health-latch checks.

Missing stores, older schemas, absent IDs, incompatible registries, malformed
JSON, substituted sources, projected-column contradictions and missing custody
fail without success output. Inspection does not repair or migrate such data.

## Access and privacy

Access to the explicitly selected local file is the read boundary. Verified
signatures authenticate custody provenance; they do not authenticate or grant
permission to the person reading it. The command adds no remote endpoint, tenant
authorization mapping or read role.

Stdout can include sensitive mission, principal, issuer, scope, evidence-digest
and reported object metadata. Treat it as mission-sensitive information and use
appropriate local file permissions and terminal/log handling. It contains no new
provider credential or raw evidence-byte export, but that does not make all
metadata public.

An HTTP or multi-tenant reader needs its own explicit tenant/resource and read
authorization binding before publication. This local command does not supply
that binding. It also does not contact a provider, observe cloud controls,
activate a lifecycle, qualify a candidate or grant action authority.

See the [durable metadata boundary](provider-evidence-repository-durable-metadata-offline.md)
and [content-only validator](provider-evidence-repository-authentication-offline.md).
