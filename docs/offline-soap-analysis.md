# Supplied WSDL and SOAP structural analysis

`sunderkey.offline_soap_analysis` implements a bounded, passive contract-instance
algorithm for specialist `AOE-GB-D06-S04`, capability `army.gb.d06.s04`, vector
`AV-GB-D06-S04-01`, package `IWP2-AOE-GB-D06-S04` in wave `IW2-011`. Its commander
is `AOE-GB-D06-CMD` and validator profile is `AOE-HQ-34`. This is partial offline
algorithm coverage, not specialist completion, activation, validation by that
profile, runtime integration or qualification.

The caller supplies native UTF-8 WSDL bytes, native UTF-8 SOAP envelope bytes,
two descriptive source IDs, one explicit operation selection and all six cost
limits. There are no callbacks, file readers, URL retrievals, schema resolvers,
credentials, signing keys, processes or target interactions. Source IDs are
labels, not authenticated origins. No request, exploit or payload is generated.

## API

All parameters are keyword-only:

```python
analyze_soap_contract_instance(
    *,
    wsdl_content: bytes,
    envelope_content: bytes,
    wsdl_source_id: str,
    envelope_source_id: str,
    selection: dict,
    limits: SoapAnalysisLimits,
) -> SoapAnalysisReport

verify_soap_contract_instance(
    *,
    report: SoapAnalysisReport,
    wsdl_content: bytes,
    envelope_content: bytes,
    wsdl_source_id: str,
    envelope_source_id: str,
    selection: dict,
    limits: SoapAnalysisLimits,
) -> SoapAnalysisReport
```

Selection has exactly these fields:

```python
selection = {
    "binding_qname": "{urn:fixture}FixtureSoapBinding",
    "operation_name": "Lookup",
    "message_kind": "request",
    "fault_name": None,
    "observed_action": "urn:fixture:lookup",
}
limits = SoapAnalysisLimits(
    max_wsdl_bytes=8192,
    max_envelope_bytes=8192,
    max_xml_tokens=2048,
    max_xml_nodes=1024,
    max_xml_depth=32,
    max_observations=128,
)
```

`message_kind` is `request`, `response` or `fault`. Only a fault selection has a
non-null `fault_name`. The binding is an expanded namespace QName, not a local
name lookup. The caller-declared action is already decoded metadata, not a raw
HTTP header or independently observed transport fact. Missing action (`None`)
and empty action (`""`) remain distinct. Request action is compared exactly with
the selected WSDL `soapAction`, including relative or empty values. A supplied
response/fault action remains unassessed, rather than being treated as a request
action or authenticated evidence.

## Closed supported subset

The contract must be WSDL 1.1 with one inline XSD schema, named global elements,
element-based message parts, a selected SOAP 1.1 HTTP document-style binding and
literal body/header/fault declarations. The selected binding, abstract
operation, input/output or named fault, message, part and inline element are
joined exactly. Each QName reference is resolved under the namespace scope of
its own XML node. Local-name fallback and invented operation wrappers are not
used. One literal part appears directly inside the SOAP Body; a named WSDL
operation need not have the same name as that part's element.

An explicit `soap:body parts` list is split only on XML space, tab, CR and LF,
then checked against the supported ASCII part-name subset. Other Unicode
whitespace is not collapsed into a valid selected name. Omitting `parts` keeps
the declared message parts; explicitly selecting one part from a multipart
message is supported, but selecting multiple body parts is outside this subset.

Inline elements are either `xs:string`, `xs:boolean`, `xs:int`, `xs:decimal` or an
anonymous complex type containing a direct sequence of these scalar elements.
Local element qualification follows `elementFormDefault` and explicit `form`.
Sequence order, missing or extra fields, occurrence counts and scalar structure
are checked. Occurrence ceilings stay compact; `unbounded` does not expand a
range. Finite occurrence lexicals are ASCII digits of at most five characters
and at most 50,000. This is a software subset ceiling, not an XSD language limit.

Boolean, integer and decimal scalar checks apply the XSD XML-whitespace rule:
leading/trailing space, tab, CR and LF may be removed; internal whitespace does
not become digits. Boolean accepts `true`, `false`, `1` and `0`. Integer accepts
ASCII decimal signs/digits within the signed 32-bit `xs:int` range. Significant
digit length is bounded before integer conversion, including arbitrarily many
leading zeroes within the source text limit. Decimal accepts ASCII decimal
lexicals without exponent notation. String contents remain opaque. No scalar
value, header contents or parsed application body is copied into the report.

The envelope uses the exact SOAP 1.1 namespace and an optional Header before one
Body. The selected body element is checked against its inline declaration.
SOAP 1.1 `mustUnderstand` is checked as `0` or `1`, separately from XSD boolean
lexicals. Unknown namespace-qualified headers are **unassessed**, not inherently
illegal and not silently approved. Known header structure is still checked.
Receiver processing of a mandatory header or an explicit actor is unassessed.
Absent or repeated declared headers are also unassessed because this subset
does not invent requiredness or processing/cardinality rules for them.

A selected declared fault checks the SOAP Fault, its unqualified
`faultcode`/`faultstring` fields, optional `faultactor`/`detail`, QName-resolvable
fault code and the exact single literal detail element. Fault code text is not
an authenticated issuer or proof of receiver behavior. The subset requires a
fault to be the sole Body child; an otherwise shaped SOAP 1.1 body containing a
fault plus other entries is marked unsupported, not called a universal SOAP
1.1 violation.

The algorithm is not a complete WSDL/XSD validator. It parses the inline
declarations and selected operation relations described above; unselected
binding internals, services/endpoints and all abstract operation relations are
not exhaustively validated. SOAP 1.2, WSDL 2.0, XML-RPC, RPC/encoded bindings,
multiple body parts, schema imports/includes, named or nested complex types,
choices, wildcards, xsi overrides, MTOM and WS-Security processing are outside
this subset. Known unsupported constructs yield an unsupported report or an
input error, never a claim of full schema validity.

## Cost bounds and unsafe XML refusal

Every limit is a required exact native positive integer. Per-source byte
ceilings are at most 1 MiB, XML token and node ceilings at most 50,000, XML depth
at most 64, and report observations at most 2,048. No observation truncation is
treated as successful analysis.

Before Expat is created, a bounded linear scan charges markup/text tokens,
elements, attributes and depth, and rejects DTDs, entity declarations, CDATA and
processing instructions other than an initial UTF-8 XML 1.0 declaration. Expat
then checks XML well-formedness, namespace scopes and actual node/depth limits.
Namespace contexts use immutable local binding frames shared by descendant
nodes, rather than copying all inherited bindings at every node. A node without
new declarations reuses its parent's frame. Local declarations are charged by
the source/node bounds before frame allocation; QName lookup walks no more than
the bounded XML ancestor depth, preserving local overrides and default namespaces.
Comments and predefined/numeric XML character references are supported. XML
includes, WSDL imports and XSD includes/imports are denied without resolving
them. Text retained for one node is at most 8,192 UTF-8 bytes. XML names use an
explicit bounded ASCII name subset.

Native selection/report documents have an independent per-document 1 MiB
canonical ASCII-JSON ceiling, depth 32, 50,000 value nodes, 8,192-byte strings
and integers of at most 63-bit magnitude. Repeated shared subtrees and JSON
escape costs are charged before serialization. Raw JSON also has a depth/value
token preflight before decoding, duplicate-key rejection, an explicit bounded
integer parser before conversion, and no floats/nonfinite numbers. Container,
string, bytes and integer subclasses, boolean-as-integer aliases and incomplete
typed wrappers are rejected at public boundaries. These limits are local
software-cost bounds, not target budgets or claims about server cost.

## Report integrity and source replay

Reports are detached unsigned canonical JSON. `SoapAnalysisReport.to_dict()`
returns a fresh native document. `to_json()` is canonical; `from_dict()` and
`from_json()` validate native shape, status/count consistency and the schema-1
`SOA-` ID/SHA-256 under domain `sunderkey.offline-soap-analysis.v1`.
Standalone JSON content integrity does not independently prove the supplied
conclusions: a coherently readdressed false observation can remain structurally
self-consistent.

The source verifier reruns the algorithm with the exact supplied WSDL/envelope
bytes, both source IDs, selection and limits. Canonical equality to this fresh
result rejects coherently rehashed false observations, derived counts and
source/configuration substitutions. Even whitespace or namespace-prefix
permutations change exact source hashes, although expanded structural names
can remain equivalent. The verifier returns a new detached existing report.

Status is `unsupported`, `mismatch`, `partially_assessed` or
`consistent_with_supported_subset`, in that precedence order. The last status
means only that these supplied bytes passed this finite subset's checks.
Malformed, unsafe, inconsistent source references or excessive inputs raise
`SoapAnalysisError`; they are not converted into a clean negative result.
Observation metadata contains structural names/counts and lexical categories,
not raw application text.

All operational effects remain `none`. All positive-use, qualification,
full-XSD-validity, receiver-processing, transport-authentication,
security-finding and server-safety flags remain false. This is not an
authorization check, authenticated mapping, signature verifier, exploit or
DoS detector, live endpoint probe, privacy/redaction guarantee, current-use
permission or production readiness evidence.

## Primary standards and regression evidence

The closed subset follows the selected parts of the
[WSDL 1.1 Note](https://www.w3.org/TR/2001/NOTE-wsdl-20010315),
[SOAP 1.1 Note](https://www.w3.org/TR/2000/NOTE-SOAP-20000508/),
[XML Namespaces](https://www.w3.org/TR/xml-names/) and
[XSD datatypes](https://www.w3.org/TR/xmlschema-2/).
The selected body-parts tokenization follows the WSDL `NMTOKENS` declaration
and [XML whitespace grammar](https://www.w3.org/TR/xml/#NT-S), not general Unicode
whitespace normalization.
These standards contain features intentionally not implemented here.

`tests/agents/test_offline_soap_analysis.py` uses wholly synthetic WSDL and
envelope bytes for valid request/response/fault cases, exact namespace joins,
sequence/scalar/header behavior, unsupported features, malformed XML,
pre-parser/pre-hash budgets, native wrapper boundaries and false readdressed
report replay. Additional controls cover XML-only part-list whitespace,
scoped namespace overrides and linear retained namespace-binding storage.
It pins the integration fixture at
`SOA-F445D28C6C836F35ABD88CEA86CD90C8`. These software tests do not supply live
provider, receiver, deployment, qualification or specialist activation proof.
