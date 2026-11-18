# Supplied OCI blob-graph integrity

This partial offline component compares supplied OCI descriptors with actual
supplied byte content. It is not registry evidence, signed origin, authenticated
provenance, an SBOM assessment or an image safety decision. Every operational
effect remains `none`. D016 live-use and qualification gates remain unchanged.

Ownership is `AOE-GC-D17-S10`, capability `army.gc.d17.s10`, vector
`AV-GC-D17-S10-01`, work package `IWP2-AOE-GC-D17-S10`, wave `IW2-022`, commander
`AOE-GC-D17-CMD`, group owner `AOE-HQ-05` and independent validator `AOE-HQ-19`.
The blueprint digest is
`sha256:745ed6b69bd9b2e3b458debe7f1a4c8bd24ab5073b75d86599ab75fe78d841fd`.
Initial roadmap evidence belongs to the existing blocked `A7.4` candidate package;
this leaf does not complete the specialist or its ten candidate components.

## Exact supplied input

The native model has exactly three fields:

```json
{
  "schema_version": 1,
  "root_descriptor": {
    "mediaType": "application/vnd.oci.image.index.v1+json",
    "digest": "sha256:<64 lowercase hexadecimal characters>",
    "size": 123
  },
  "blobs": [
    {"digest": "sha256:<64 lowercase hexadecimal characters>",
     "content_base64": "<canonical standard base64 of the exact supplied bytes>"}
  ]
}
```

The example is a shape illustration, not valid addressed content. Blob records
are closed and digest keys must be unique. Empty byte content has empty base64.
Canonical base64 includes correct padding and padding bits. List order is retained.
No source pathname, credential, registry client, URL fetching or callback is used.

The APIs are `analyze_supplied_oci_blob_graph(model)`,
`analyze_supplied_oci_blob_graph_bytes(model_bytes=...)` and
`verify_supplied_oci_blob_analysis(report, model=...)`. The owned `OciBlobAnalysis`
wrapper supports `from_dict`, `from_json`, `to_dict` and `to_json`.

## Finite semantics

The pinned basis is OCI image-spec v1.1.1:
[descriptors](https://github.com/opencontainers/image-spec/blob/v1.1.1/descriptor.md),
[image indexes](https://github.com/opencontainers/image-spec/blob/v1.1.1/image-index.md)
and [image manifests](https://github.com/opencontainers/image-spec/blob/v1.1.1/manifest.md).

All blobs are prebounded before decoded allocations and content hashing. Exact
content SHA-256 is checked before consuming referenced OCI JSON. Every supported
descriptor must resolve to supplied content with matching byte size and digest.
Size mismatches prevent JSON consumption. Index and manifest documents expand
iteratively once per content address; every incoming descriptor is checked even
when its child is shared. A linear topological calculation measures the longest
supplied path rather than enumerating all possible paths through a shared DAG.

Known OCI indexes and image manifests use native integer `schemaVersion: 2`.
Their optional `mediaType`, if supplied, must be a native string. The component
preserves config/layer descriptor order. Configuration and known layer-media
bytes are opaque: a passing byte check does not establish JSON config correctness,
tar validity, decompression safety, filesystem changes, `diff_ids`, runtime
compatibility or image executability. An empty index or empty layers array is
not rejected merely for being empty.

Optional descriptor metadata, `urls`, embedded `data`, `platform`, `artifactType`,
document `subject` and other fields are retained but unassessed. No links in those
fields are followed and their presence withholds complete graph conclusions.
Unknown digest algorithms, future schema versions, media types or media-role
interpretations are also unassessed. A repeated digest with distinct media
interpretations is not declared universally invalid OCI; this single-type graph
profile returns incomplete. Distinct declared sizes cannot both match the same
exact content and are recorded as a supplied integrity conflict.

The result has `verdict: pass`, `fail` or `incomplete`. `pass` means only that the
supported supplied graph closes with exact byte checks. Missing referenced blobs,
SHA-256 mismatches and size contradictions produce `fail`, not a claim that a
remote registry or an original OCI artifact is invalid. Unsupported semantics
produce `incomplete`; known byte failures still dominate that verdict. Invalid
closed models and software-budget refusals raise `OciBlobAnalysisError` instead
of returning a positive or partial receipt.

## Ownership, replay and publication warning

Reports retain the complete original model, including every supplied base64 blob.
They are **not sanitized for publication**. Do not supply secrets or assume that
configuration or layer bytes are safe to display. The module performs no file
publication, redaction or secret classification.

Content digests cover original bytes, including JSON whitespace and key spelling.
Source/report addresses use separate canonical JSON domains only after the full
retained report passes its cumulative budget. The wrapper reconstructs the
embedded original model on import and export; coherently rehashed false results
are denied. The separate verifier also compares against separately supplied
originals. Returned data is detached. These local guarantees do not authenticate
a caller-selected root, registry, signer, current content or current authority,
and do not isolate the process from deliberately malicious injected Python code.

## Software ceilings

- Model JSON: 1 MiB; report JSON: 2 MiB.
- At most 128 supplied blobs, 256 KiB each and 512 KiB aggregate decoded bytes.
- At most 2,048 descriptor occurrences, 32 graph levels and 4,096 findings.
- Native model/report nodes: 32,768/65,536; depths: 16/20.
- Processing work: 2,000,000 charged units per reconstruction pass, covering
  supplied base64 characters, exact content bytes, consumed OCI JSON bytes,
  descriptor visits and graph work.

Native collections and primitives must be exact built-in JSON families. Floats,
subclasses, cycles, Boolean/integer aliases in integer fields and nonnative byte
inputs are refused. Integers use a signed63-magnitude software subset. OCI JSON
uses printable ASCII strings and integer-only numbers; these intake restrictions
are not a claim that wider valid OCI JSON is universally malformed. Raw JSON
nodes, scalar depth, integer grammar and escaped strings are bounded before the
decoder; duplicate fields are rejected. Cumulative escaped-byte and node costs
are charged before retaining result rows or performing source/report addressing.

The focused tests include exact supplied byte spelling, shared DAGs, missing and
swapped content, contradictory sizes, actual raw JSON type aliases, independent
tiny-graph checks, native/raw cost limits, detached exports and false cohashed
claims. Synthetic outcomes do not provide containment or deployment acceptance.
