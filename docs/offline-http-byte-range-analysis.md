# Supplied HTTP bytes-range arithmetic

This offline component examines one caller-supplied `Range` field value and a declared
representation length. It is a partial, unsigned calculation for
`AOE-GB-D05-S01` / `army.gb.d05.s01` / `AV-GB-D05-S01-01`, work package
`IWP2-AOE-GB-D05-S01`, wave `IW2-001`, commander `AOE-GB-D05-CMD`, group
`AOE-HQ-04`, and independent validator `AOE-HQ-34`. The existing blueprint
digest is `sha256:fa6415a05aa9b97e2ca9fa46194d2adc43bb4aabd2a4cfe3b171215d52b18532`.
The component ID is `http_supplied_byte_range_arithmetic`; initial evidence
is A7.4 only. It does not complete or qualify a specialist.

Primary source:
[RFC 9110, sections 14.1 and 14.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-14.1).
The implementation supports the `bytes` range unit, decimal `first-last`,
`first-`, and `-suffix` members, optional spaces or tabs around comma-separated
members, and a bounded number of empty list elements accepted under RFC 9110
section 5.6.1.2. It retains original member spelling and order. Positions are
zero-based; a selected last position is inclusive. A present last position
earlier than first is invalid. A large or open end is clamped to the last
available octet of the declared representation.

The RFC GET satisfiability predicate and concrete selected octets are separate.
A nonzero suffix is satisfiable under section 14.1.2 even when the declared
representation length is zero, in which case this report has no selected
first/last octet and selects zero octets. A zero suffix is not satisfiable.
The report also lists pairwise overlap among nonempty selected spans; it does
not combine spans or predict response formatting. Empty list elements are
counted, not treated as a transmitted recommendation.

Public APIs are `analyze_supplied_http_byte_ranges(model)`,
`analyze_supplied_http_byte_ranges_bytes(*, model_bytes=...)`, and
`verify_supplied_http_byte_range_analysis(report, *, model=...)`.
`HttpByteRangeAnalysis` offers exact `from_dict`, `from_json`, `to_dict`, and
`to_json` methods. `component_fixture()` returns fresh inert declarations.
The closed source model has exactly four fields:

```json
{
  "schema_version": 1,
  "source_id": "synthetic-range",
  "range_field_value_base64": "Ynl0ZXM9MC00LCAxMC0sIC0z",
  "representation_length": 20
}
```

The base64 text is canonical standard base64 of exactly the supplied field
value bytes, not an entire HTTP message. A source ID is a bounded caller label.
The report retains this owned source model and SHA-256 addresses the canonical
parsed source and derived report under distinct local domains. These hashes
are mechanical change detectors, not source authentication. Separately
supplied original-model verification recomputes the entire report; self-contained
round trips alone are not original-source verification. Output is detached and
has all authority and effect fields set to false or `none`.

Software ceilings are 8192 field bytes, 128 nonempty members, 128 empty list
elements, 256 retained overlap pairs, 16 KiB model JSON, 256 KiB report JSON,
signed64 positions and representation length, 12 JSON depth, 256 model nodes,
4096 report nodes, and 8 MiB cumulative work per public operation. Native and
raw JSON families are bounded before decoding, copying, allocating large
results, or digesting. Exhausting these ceilings is a domain rejection, not
an HTTP syntax conclusion. The raw bytes API accepts ASCII JSON, rejects
duplicate object members, floats and numeric aliases, and retains the canonical
parsed snapshot rather than claiming provenance of the raw wrapper bytes.

No GET request, method, `If-Range`, precondition, response, server policy,
representation identity, multipart boundary, or live network context is
supplied. RFC 9110 allows a server to ignore Range and, for example, to reject
many small or overlapping ranges. This component cannot establish whether a
server honors the field, produces 206 or 416, or sends any octets. It does not
authorize traffic, prove a vulnerability, or create qualification evidence.
