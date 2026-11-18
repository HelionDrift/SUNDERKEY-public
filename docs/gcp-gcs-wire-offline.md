# GCS JSON API wire codec, offline only

`sunderkey.gcp_gcs_wire` describes requests and decodes explicitly supplied raw
response bytes. It is inert software. There is no HTTP client, transport,
dispatch method, SDK, credential resolution, IAM/provisioning, signing, retry,
redirect following, target interaction or automatic rollback. The environment
class remains `reference_simulation_nonqualifying`. Synthetic fixtures are not
provider observations, D013 accepted ingest controls, authenticated custody,
D014 selection or qualified readiness.

## Four inert request descriptions

| API | Explicit inputs | Description |
| --- | --- | --- |
| `describe_bucket_lookup` | Exact `GCSBucketProfile` | Live bucket metadata GET with a narrow policy field selector |
| `describe_live_object_metadata` | Profile and exact local object name | Current live object metadata GET, no historical revision selector |
| `describe_pinned_media_read` | Profile, exact `GCSReadRequest`, `GCSWireObjectObservation` | Live media GET with both generation and metageneration match conditions |
| `describe_conditional_object_write` | Profile and exact `GCSWriteRequest` | Conditional multipart object POST with exact metadata and raw payload bytes |

`GCSWireRequest` contains fixed method/URL/header/body bytes plus canonical,
detached source fields. Each public response parser recaptures and reconstructs
the frozen description, including typed source records, before interpreting a
response. Reassigned fields, native-scalar aliases, unsupported subclasses,
endpoint changes, substituted names and modified conditions fail closed.

The origin is always `https://storage.googleapis.com`. Bucket and object names
are encoded as individual URI path components, including the slash in
`ledger/OBJECT` or `heads/DEPLOYMENT`. No arbitrary endpoint, credential header,
ACL, KMS override, resumable session, media URL from a response or custom query
is accepted. Request headers ask for identity encoding; the codec performs no
compression or decompression.

Google documents the [object GET endpoint and conditions](https://docs.cloud.google.com/storage/docs/json_api/v1/objects/get),
[object insertion endpoint and multipart/create-only conditions](https://docs.cloud.google.com/storage/docs/json_api/v1/objects/insert),
[bucket GET endpoint](https://docs.cloud.google.com/storage/docs/json_api/v1/buckets/get)
and [URI component encoding](https://docs.cloud.google.com/storage/docs/request-endpoints).
These references define wire syntax, not permission to issue the descriptions.

## Current live reads, not revision-selected custody

The pinned media description uses `alt=media`, `ifGenerationMatch` and
`ifMetagenerationMatch`, with no `generation` query parameter. The live-object
default is intentional: Google documents `generation` as a revision selector.
A successful generation-selected read could describe historical bytes and must
not be mislabeled as current live custody. This codec has no historical,
soft-deleted, restore-token or generation-selected helper.

Metadata parsing rejects `timeDeleted`, `softDeleteTime`, `hardDeleteTime`,
object `retention` configurations and active temporary/event holds. Stored
content must be `application/octet-stream` without a nonidentity encoding.
Responses using another media type or fractional/non-UTC retention timestamps
are outside the current supported subset. The existing typed custody mapping
accepts exact whole-second UTC retention timestamps; the codec does not truncate
or round a provider timestamp into a weaker retention assertion.

## Local descriptor metadata convention

Ledger object uploads store exactly one custom metadata entry named
`sunderkey-ledger-object-descriptor-v1`. Its string value is the existing
`LedgerObjectDescriptor` canonical JSON bytes decoded as ASCII, with all six
fields: object ID, SHA-256, byte size, required retention time, declared logical
namespace and declared failure domain. The request must be create-only, its
name and payload must reproduce that descriptor, and its logical labels must
match the explicitly supplied profile.

This is a local mapping convention using Google custom metadata strings. It is
not a GCP-native signed descriptor, namespace attestation or failure-domain
authentication. Head objects have no ledger descriptor or retention metadata.
Their provider generations are fencing tokens, not logical ledger sequence
numbers. The codec never derives a logical sequence from a provider generation.

The multipart body has a deterministic collision-checked boundary, a canonical
JSON metadata part, and a raw `application/octet-stream` payload part. Binary
payloads are preserved byte for byte. It sets the exact body `Content-Length`
and a locally computed CRC32C. [Google's upload guide](https://docs.cloud.google.com/storage/docs/uploading-objects)
describes the JSON API multipart structure; this implementation does not execute
that guide's credential or upload steps.

## Narrow unsigned responses

`parse_bucket_response` returns `GCSBucketObservation`, which contains only
returned bucket name, metageneration, versioning and retention facts. It never
adds the profile's namespace/failure-domain labels as authenticated observations.
The supplied declaration is separate from the unsigned response. Explicit
`versioning.enabled` is required; omitted policy facts do not become a false
value by fallback. A missing retention policy is supported only for the declared
unlocked, zero-retention head bucket. A locked ledger bucket must return its exact
locked retention period. Object retention mode, default event holds and deleted
bucket observations are unsupported.

`parse_object_metadata_response` returns `GCSWireObjectObservation`, containing
the existing typed live-object metadata and optional CRC32C. Exact requested
bucket/name, canonical decimal generation/metageneration/size strings, local
descriptor bytes and sufficient reported retention must agree. A conditional
write acknowledgement must reproduce payload size and descriptor, match any
returned CRC32C and advance the provider generation for replacement. An upload
acknowledgement alone is not D013 accepted ingest or an immutable catalog claim.

`parse_media_response` returns an existing `GCSObjectRead` only when full raw
bytes reproduce the pinned metadata size, any supplied CRC32C and the ledger
descriptor SHA-256. Google permits omitted CRC32C for some encrypted objects;
absence does not fabricate a checksum. Ledger SHA-256 verification remains
mandatory. These are local checks on supplied bytes, not provider authentication.
Current retention activity, declared retention horizon, whole-port conformance
and custody authority remain the responsibility of the existing custody layer
and separately authorized infrastructure proof.

The [object resource reference](https://docs.cloud.google.com/storage/docs/json_api/v1/objects)
defines string counters, CRC32C, custom metadata strings, hold and retention
fields. The [bucket resource reference](https://docs.cloud.google.com/storage/docs/json_api/v1/buckets)
defines versioning, retention lock and policy period fields.

## Error and input bounds

Only status 200 is parsed as a supported response. Status 412 maps to the
existing `GCSPreconditionFailed` only for a conditional write or pinned media
read. It is not a logical policy rejection: the existing custody layer must
perform its own subsequent read and conflict/content checks. Other write
statuses are `GCSAmbiguousWrite`, with no confirmed rollback or automatic retry.
Other read statuses, including 404, redirects and partial 206 responses, remain
unsupported/unconfirmed errors. The codec does not turn an unavailable read into
an observed missing object.

Responses are native bytes, bounded before UTF-8 decoding. JSON is limited to
16 KiB, depth eight and 256 nodes, with native bounded printable ASCII keys and
strings. Duplicate decoded keys, arrays, floats, nonfinite numbers, integer
overflow and unsupported fields are rejected. Descriptor strings are bounded
to 8 KiB and must reproduce the exact canonical local descriptor. Aggregate
serialized bytes, including escapes and punctuation, are charged before JSON
serialization. Payloads retain the existing 16 MiB object and 4 KiB head limits;
multipart overhead has its own fixed bound.

The tests use only local synthetic byte fixtures. They exercise all four
descriptions, negative raw responses and composition with the unchanged D012
ledger/head ports. No real request is sent and no provider, deployment,
credentials, regional custody, parity or qualification claim is produced.
