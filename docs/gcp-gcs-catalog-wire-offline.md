# GCS catalog wire codec, offline only

`sunderkey.gcp_gcs_catalog_wire` describes requests and verifies explicitly
supplied response bytes for the existing bounded catalog simulation port. It
has no HTTP client, SDK, transport, dispatch method, credential lookup, IAM,
signing, provisioning, retry, redirect following, decompression or rollback.
Its environment remains `reference_simulation_nonqualifying`. No synthetic
result selects D014, accepts D013 custody, qualifies a provider or grants use.

## Explicit descriptions and source replay

The four APIs are `describe_catalog_bucket_lookup`,
`describe_catalog_live_metadata`, `describe_catalog_pinned_media_read` and
`describe_catalog_create_only_write`. They require the exact existing finite
simulation profile. Bucket and metadata lookups require an explicit native
aware UTC `observed_at`; reads and uploads use the exact instant in their
existing catalog request. No current-time default exists. Microseconds and
the native UTC datetime components are preserved without truncation. Captured
components are bounded to the native UTC datetime calendar before reconstruction.

`GCSCatalogWireRequest` contains canonical detached source JSON, raw payload,
and exact method, URL, headers and body bytes. Every response parser replays
the profile hash, source coordinates, request families, timestamp and pinned
observation before interpreting status or response bytes. Native aliases,
missing or changed fields, substituted endpoints, credentials and changed
preconditions fail closed. Caller labels and observation time are not Google
authentication or a fresh infrastructure observation.

The supported provider retention interval is 1 through 3,155,759,999 seconds.
The existing simulation contract accepts its inclusive 3,155,760,000 upper
bound; this codec rejects that unsupported endpoint without changing the
contract. Google specifies a positive period strictly below that endpoint in
the [bucket resource reference](https://docs.cloud.google.com/storage/docs/json_api/v1/buckets).
No period, use horizon or retention lock is supplied by default or applied.

## Stable objects and current-live requests

The fixed origin is `https://storage.googleapis.com`. Names are encoded as
single URI components. Stable keys are `catalog/{object_id}`, not digest-only
paths or mutable latest aliases. Metadata GET selects the current live object.
Pinned media GET uses both `ifGenerationMatch` and `ifMetagenerationMatch`
without the historical `generation` selector. There are no historical,
soft-delete, restore, partial-range or arbitrary query helpers.

Uploads are deterministic multipart POST descriptions with
`ifGenerationMatch=0`, no metageneration condition, exact binary payload,
`Content-Length` and locally computed CRC32C. The collision-checked boundary
is deterministic from the captured sources and payload digest. No ACL or
encryption override is added. Such a description does not establish encryption,
actual publication or a conditional write applied by a provider.

The local custom metadata key is `sunderkey-catalog-object-descriptor-v1`.
Its string value is exact canonical ASCII JSON for the five existing descriptor
fields: object ID, SHA-256, size, namespace and failure domain. It is not a
signed descriptor or authenticated domain label. Ledger descriptors, alternate
keys, unknown custom metadata, changed labels and noncanonical bytes reject.

Google documents the [object GET conditions](https://docs.cloud.google.com/storage/docs/json_api/v1/objects/get),
[object insertion and multipart fields](https://docs.cloud.google.com/storage/docs/json_api/v1/objects/insert),
[request preconditions](https://docs.cloud.google.com/storage/docs/request-preconditions)
and [URI component encoding](https://docs.cloud.google.com/storage/docs/request-endpoints).
These references define syntax, not authorization to send a request.

## Unsigned responses and finite protection

`parse_catalog_bucket_response` returns only selected unsigned bucket facts.
It never adds namespace, failure-domain, account, observation-time or currentness
labels from the profile. Disabled versioning, a locked matching retention
policy and false default hold must be explicit native response facts. Any
object-retention configuration or deleted bucket field is unsupported. The
returned missing-configuration fact is not authenticated disablement or proof
of effective policy. A future adapter must keep declarations and time separate.

`parse_catalog_object_response` returns an owned existing catalog observation
plus optional CRC32C. Its timestamp is explicitly caller-labeled, not a provider
timestamp. The selected current-live shape, coordinates, positive provider
tokens, descriptor and size must agree. Temporary and event holds must be
explicitly false. Object-level retention and deleted versions reject. Stored
media must be `application/octet-stream` with no nonidentity encoding.
If present, `contentEncoding` must be the native string `identity` and `crc32c`
must be a native canonical checksum string. Explicit JSON null is not omission;
it rejects before an object fact is formed. Omitted CRC remains absent, and an
explicit caller observation with `crc32c=None` still means no supplied checksum.

Provider retention must be whole-second UTC and cover the original fixed
simulation horizon. Fractional or non-UTC values are unsupported, never rounded
into a weaker assertion. Longer reported retention does not extend the source
horizon. The caller instant must remain inside the original window. This is
local supplied-data consistency, not live retention, permanent immutability or
a durable restart witness.

`parse_catalog_media_response` requires full raw bytes reproducing pinned size
and SHA-256, and any supplied CRC32C. Missing CRC does not fabricate a checksum;
SHA-256 remains mandatory. A create acknowledgement requires the exact uploaded
descriptor and any reported CRC, but is not by itself an immutable catalog or
accepted ingest receipt. The existing catalog layer still performs readback,
current bucket, horizon, collision and remembered-version checks.

The [object resource reference](https://docs.cloud.google.com/storage/docs/json_api/v1/objects)
defines counters, custom metadata, CRC32C, retention and hold fields. Responses
with omitted facts outside this explicitly supported subset remain unsupported.
Supplied status and bytes cannot prove TLS origin, Google provenance, IAM,
ownership, currentness, independent failure domains or actual retention.

## Bounds, uncertainty and software checks

Only status 200 succeeds. Conditional status 412 becomes the existing
`GCSPreconditionFailed`, not an expected policy denial. Other write statuses
remain `GCSAmbiguousWrite`; reads reject unsupported statuses, including 404,
redirects and partial responses. HTTP 404 never becomes confirmed absence.
There is no retry, fallback or inference that an uncertain write was undone.

JSON uses the existing 16 KiB, depth-eight and 256-node bounds, with native
printable ASCII values, bounded integers, no arrays, floats or nonfinite numbers,
and duplicate decoded keys rejected. Aggregate bytes, escapes and punctuation
are charged before serialization. Descriptor strings are bounded to 8 KiB.
Catalog payloads remain 1 through 16 MiB, with a separate multipart overhead
bound. Unsupported values reject before expensive conversion where practical.

Run `python -B -m unittest tests.agents.test_gcp_gcs_catalog_wire -v` with
`PYTHONPATH=src`. Local tests cover request reconstruction, native aliases,
microsecond preservation, bounds, descriptor and checksum substitutions,
holds, retention, statuses and exact payloads. A test-only raw-byte bridge
composes the unchanged catalog adapter for real synthetic create, replay,
read, collision and create-race behavior. Only its explicit in-memory state
supplies absence; the codec does not parse 404 as an absence observation.
Lost acknowledgements remain unconfirmed even when a synthetic write applied.

No operational provider request, credential, signing material, deployment,
target activity, acceptance observation or new authority is created. This
module is not a production transport or a sandbox for injected Python code.
