# Target context ingestion

Phase 159 adds an offline boundary for admitting target context before any planner,
adapter, or operational component can use it. The boundary produces a typed,
content-addressed bundle. It does not grant authority, qualify an adapter, dispatch
work, execute supplied content, or perform network access.

## Supported inputs

The boundary accepts only caller-supplied bytes or files under a caller-selected
local directory:

- OpenAPI 3 and Swagger 2 documents encoded as JSON or a deterministic safe YAML
  subset
- SOAP WSDL 1.1 and 2.0 XML documents
- ZIP source archives
- UTF-8 source files from the explicit source media allowlist
- UTF-8 Markdown, HTML, reStructuredText, AsciiDoc, and plain-text documentation
- UTF-8 free text

There is no URL input and no network fetch path. OpenAPI references, WSDL imports,
and documentation links are counted but never resolved. An external OpenAPI or
WSDL reference adds `external_reference_not_resolved` to the quarantine flags.

## Public interface

`TargetContextProvenance` binds each ingestion to a stable source ID, the supplying
principal, and a caller-provided whole-second UTC collection time. `mission_id` and
`authority_ref` are mandatory on every ingestion call and are included in the
bundle hash.

Use `ingest_target_context_bytes` for one byte sequence,
`ingest_target_context_inputs` for several byte sequences, and
`ingest_target_context_directory` for a local tree. A byte input can include an
`expected_sha256`. Directory ingestion can include an
`expected_manifest_sha256`. A mismatch is rejected as hash drift.

```python
from sunderkey.target_context import (
    TargetContextKind,
    TargetContextProvenance,
    ingest_target_context_bytes,
)

bundle = ingest_target_context_bytes(
    openapi_bytes,
    name="openapi.yaml",
    media_type="application/yaml",
    kind=TargetContextKind.OPENAPI,
    mission_id="MISSION-001",
    authority_ref="AUTH-001",
    provenance=TargetContextProvenance(
        source_id="upload.001",
        supplied_by="principal.operator.001",
        collected_at="2026-09-20T03:00:00Z",
    ),
)
```

The result validates against
`registry/schemas/target-context-bundle-v1.schema.json`. Its identity is the SHA-256
hash of canonical JSON containing the bundle domain and every field other than the
bundle ID and hash. The ID is derived from that digest. Input and artifact records
also carry hashes of the original bytes. Reordering injected inputs does not change
the resulting identity.

## Parsed facts

Only metadata and conservative structural facts enter a bundle.

- OpenAPI and Swagger facts include format, version, serialization, path and
  operation counts, HTTP method counts, schema and security scheme counts, server
  count, and internal and external reference counts.
- WSDL facts include version and counts for services, endpoints, bindings,
  operations, messages, types, and external imports.
- Documentation facts include line, word, character, heading, and link counts.
- Source and free-text facts include line, nonblank line, word, and character
  counts. Source records also include the normalized extension.

Descriptions, titles, operation IDs, service names, endpoint values, URLs, source
text, documentation text, and free text are not preserved in the bundle.

## Resource and archive policy

The default limits are:

| Limit | Default |
| --- | ---: |
| Input bytes per supplied file | 8 MiB |
| Expanded bytes per logical file | 2 MiB |
| Total supplied or expanded bytes | 16 MiB |
| Supplied or expanded file count | 256 |
| ZIP decompression ratio | 100 to 1 |
| Portable path length | 240 characters |
| Structural nesting depth | 32 |
| Redaction and quarantine findings | 256 |

`TargetContextLimits` can lower these values explicitly. The defaults are also hard
safety ceilings. The active values are recorded in the content-addressed bundle.

ZIP members are streamed in memory and are never extracted to disk. The reader
rejects encrypted entries, special files, symbolic links, nested archives,
duplicate or case-colliding paths, traversal, absolute paths, Windows drive paths,
backslashes, reserved device names, unnormalized segments, non-ASCII paths, overly
long paths, excessive file counts, excessive expanded sizes, and excessive per-file
or aggregate decompression ratios.

Directory ingestion rejects a symbolic-link root, symbolic-link descendants, and
non-regular files. It does not follow links. Each file is checked before and after
its bounded read so size, modification time, or file identity drift fails closed.
The opened descriptor is also checked as a regular file before reading. Its
nonblocking open prevents a replacement named pipe from stalling ingestion on
platforms that support the flag.

## Structured parser policy

JSON parsing rejects duplicate object keys, non-finite numbers, malformed input,
and excessive nesting. YAML uses a local deterministic parser and does not import a
general YAML runtime. It rejects multiple documents, directives, duplicate mapping
keys, inconsistent indentation, tags, anchors, and aliases. Unsafe YAML features
in an otherwise identified OpenAPI input are quarantined without evaluation.

WSDL parsing checks for `DOCTYPE` or entity declarations before XML parsing. Such a
document receives the critical `xml_doctype_or_entity` flag and is not parsed.
Malformed XML without this marker is rejected. The XML parser receives only the
already supplied UTF-8 bytes and is never configured with a resolver. Streaming
events enforce the configured structural depth and a hard ceiling of 65,536 XML
elements. A lower file-byte limit proportionally lowers the element ceiling.

## Secrets and hostile content

Text is scanned before structural parsing. Detectors cover private-key headers,
AWS access keys, common GitHub token forms, JWTs, bearer tokens, credential
assignments, and credentials embedded in URLs. The bundle stores only detector,
path, line, column, a SHA-256 digest of the matched secret, and a fixed redaction
placeholder. The matched value is never serialized.

Recognized instruction override, role impersonation, credential exfiltration,
active HTML, dangerous URI, unsafe YAML, XML entity, external reference, and secret
material signals produce quarantine flags. Any redaction or flag makes the bundle
status `quarantined` and marks the affected artifact. Quarantine is evidence, not a
permission decision. A later policy layer must decide whether and how a quarantined
bundle may be reviewed.

## Non-effects

Every valid bundle fixes authority, execution, network, and operational effects to
`none`. Ingestion performs bounded local reads only. It does not:

- resolve external references or links
- invoke a shell, interpreter, compiler, template engine, browser, or XML resolver
- import supplied source as code
- extract archives to the filesystem
- create credentials, sessions, approvals, or target authority
- mutate mission, registry, routing, qualification, deployment, or runtime state

The `TargetContextBundle.from_dict` constructor revalidates field sets, types,
ordering, path uniqueness, limit consistency, summary counts, finding bindings,
quarantine state, non-effects, and the canonical bundle identity. Use
`verify_input_bytes` when retained input bytes must be checked against a bundle
again.
