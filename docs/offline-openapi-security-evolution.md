# Offline OpenAPI security-declaration evolution

This partial REST specialist algorithm compares supplied OpenAPI 3.0.0 through
3.0.4 security declarations. It is attached to existing profile
AOE-GB-D06-S01, capability army.gb.d06.s01, vector AV-GB-D06-S01-01 and wave
IW2-008. It does not complete that specialist or establish readiness,
authorization, server behavior, vulnerability, parity or qualification.

The implementation is independent of the existing contract extractor,
one-document security matrix, local scheme audit and retest lineage. It derives
two-version symbolic implications, not another extraction or assertion wrapper.
There are no dependencies beyond the Python standard library and no callback,
network, filesystem, credential, process, request-generation or target port.

## Public API and source identity

`analyze_openapi_security_evolution(model)` accepts exactly:

```python
{
    "schema_version": 1,
    "previous_document": {...},
    "current_document": {...},
}
```

It returns an exact `OpenAPISecurityEvolutionReport`.
`verify_openapi_security_evolution(report, *, model)` reconstructs the complete
result from a separately supplied original model and returns a detached report.
`component_fixture()` returns a fresh wholly synthetic model: one
`GET /synthetic` declaration changes from bearer AND key to bearer alone.
Its relationship is `weakened`; this is not evidence of a public endpoint.

Both the entire canonical native model and the two canonical documents are
SHA-256 bound. Object-key order and JSON presentation whitespace are not source
identity; list order and every supplied source value are. Input and output
snapshots are detached. The report contains only source digests, symbolic
metadata and local analysis results, not the original documents or credentials.

`OpenAPISecurityEvolutionReport.from_dict` and `.from_json` check bounded
unsigned content, canonical formulas, internal relationships and content
addresses. They do not recover unavailable original sources. A coherently
readdressed false source-derived formula can remain internally consistent;
separate-original-model verification rejects it. Direct dataclass construction
requires the exact canonical JSON, and public use revalidates its content.
Neither hashes nor replay authenticate a source, signer, deployment or principal.

## Supported symbolic semantics

Operations are matched only by exact literal path and standard lowercase
OpenAPI method, displayed uppercase in the report. No server URL, path
normalization or endpoint equivalence is inferred. Operation-level `security`
overrides root `security`; a missing operation override inherits the root.
The algorithm preserves these distinctions:

- Missing effective security is `absent` and unassessed.
- An explicit `[]` removes the inherited declaration and has an empty symbolic
  obligation, while retaining `explicit_empty` and a zero alternative count.
- `[{}]` contains an anonymous alternative. It also has an empty symbolic
  obligation but retains `anonymous_alternative` and its declared count.
- Schemes inside a requirement are AND obligations; requirements are OR
  alternatives. OAuth scopes add AND obligations under their scheme.

Each scheme has a presence symbol and each requested scope has a separate
scheme-qualified symbol. Duplicate obligations and absorbed alternatives are
minimized deterministically. Every original referenced alternative is resolved
before minimization, so an anonymous or simpler alternative cannot hide an
undefined scheme or unsupported semantics.

For normalized monotone DNF formulas F and G, F implies G exactly when every
term of F contains some term of G. Bounded subset tests establish both
directions without enumerating truth assignments or a power set. The reported
relations are `equivalent`, `weakened`, `strengthened` and `incomparable`, with
separate implication flags and deterministic failing-term witnesses.

An exact inline operation present on only one side is `added` or `removed`;
these rows do not claim a security implication. A reference-only path does not
invent an operation. Opaque path or operation references withhold comparison,
including when the other version has an inline method. `opaque_paths` records
that limitation separately.

## Local definitions and withheld conclusions

Only self-contained local apiKey, HTTP basic/bearer and the four OpenAPI OAuth2
flow declarations are supported. The local URL subset is absolute HTTPS with
no user information; URLs are checked syntactically and never fetched.
Requested OAuth scopes must occur in the supplied flow scope maps. Non-OAuth
scope lists must be empty. Different flows or definitions do not establish
actual credential rights.

For a common operation, every scheme referenced on either side must resolve
to the exact same complete local definition in both documents. A changed
description, URL, bearer format or definition also conservatively withholds
the comparison. Unreferenced definition changes remain source-bound but do not
change the symbolic relation.

An unresolved alternative, missing definition, scheme reference, unknown type,
unsupported HTTP scheme, incomplete OAuth flow, undeclared scope, non-OAuth
scope, external OpenID Connect discovery or unsupported extension/field at an
analyzed container yields `unassessed`. No reference, discovery, fallback or
extension interpretation runs. The report's `complete` analysis status means
only that its declared operation comparisons fit this supported subset.

This is not full OpenAPI validation. Other standard metadata, schema, response,
parameter and callback contents remain source-bound but are not interpreted.
Unused security declarations and unreferenced definitions do not receive a
full specification validation. Missing security does not prove anonymous access;
equivalence does not prove authorization correctness.

## Closed native and software-cost limits

The model and each report have independent 1 MiB aggregate canonical ASCII
JSON budgets. The model budget covers both documents together. Only exact
native dictionaries with native string keys, lists, valid Unicode strings,
booleans, null and signed 64-bit integers are admitted. Floats, tuple/mapping
substitutes and subclasses are rejected even in otherwise uninterpreted
source metadata. Security shape and report schema/count fields have their own
exact primitive checks; booleans are not integers there.

Fixed caps are recorded in the report:

| Cost | Ceiling |
| --- | ---: |
| Aggregate canonical bytes | 1,048,576 |
| Native depth / nodes | 32 / 50,000 |
| Individual string UTF-8 bytes | 8,192 |
| Union operation rows | 512 |
| Alternatives per effective declaration | 64 |
| Raw atoms per alternative | 128 |
| Raw atom occurrences across comparisons | 16,384 |
| Local scheme definitions per document | 256 |
| Charged symbolic subset-comparison work | 1,000,000 |
| Issue occurrences | 2,048 |

Referenced scheme names use the ASCII component-name subset of 1 through 128
characters. Literal paths are limited to 1,024 UTF-8 bytes; scope symbols must
be nonempty, control-free strings of at most 256 UTF-8 bytes. No trimming,
Unicode normalization or scope equivalence is inferred.

Queued children, repeated shared subtrees, escaped string costs and integers
are checked before native serialization or new hashes. Raw report JSON is
byte-, decoded-string-, escaped-output-, depth-, node- and integer-bounded
before decoding. Duplicate keys, floats, nonfinite values and unpaired
surrogates are rejected. Symbolic work is charged before subset comparisons;
conservative output capacity is reserved before derived row/group copies.
These are local software-cost ceilings, not runtime or lease authority.

Referenced definition structure and canonical identity are cached once per
owned document/name. Cross-version definition equality is cached once per
name. Scope obligations are aggregated in one bounded atom pass, avoiding
repeated full scope-map scans or definition serialization for every operation.
Native source traversal and these one-time definition passes are separately
bounded by the document caps; `work_units` is the charged subset-comparison
metric, not a measurement of CPU time or all Python instructions.

All effects remain `none`; positive-use approval, target authorization,
credential rights, server behavior, full specification validation and
qualification flags remain false. No parsing result grants live permission,
invokes an adapter or promotes an original reference candidate.

## Primary specification

The rules follow the OpenAPI 3.0.4
[Operation Object](https://spec.openapis.org/oas/v3.0.4.html#operation-object),
[Security Requirement Object](https://spec.openapis.org/oas/v3.0.4.html#security-requirement-object)
and [Security Scheme Object](https://spec.openapis.org/oas/v3.0.4.html#security-scheme-object).
The supported subset and uncertainty above are narrower than full OpenAPI.
