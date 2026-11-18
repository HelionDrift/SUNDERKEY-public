# Supplied SAML Conditions and AudienceRestriction arithmetic

This partial, offline R0 component is bound to `AOE-GA-D03-S03`,
`army.ga.d03.s03`, `AV-GA-D03-S03-01`, `IWP2-AOE-GA-D03-S03`,
`IW2-004`, `AOE-GA-D03-CMD`, `AOE-HQ-03`, and independent validator
`AOE-HQ-19`. Its source blueprint is
`sha256:604c5aaf9d3a4cabccc1e0ff194a70a383af1ec16ce44bd0f0eb739911041352`.
It is A7.4 partial repository evidence, not specialist qualification.

The primary semantic source is the [OASIS SAML 2.0 Core standard, 15 March
2005](https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf),
especially sections 1.3.2-1.3.3 and 2.5.1.1-2.5.1.4. The result applies
its condition precedence: a known false condition dominates an unsupported
condition; otherwise an unsupported condition remains indeterminate. The
`NotBefore` bound is inclusive, `NotOnOrAfter` is exclusive, audiences within
one restriction are OR alternatives, and multiple restrictions are ANDed.
The report never calls these arithmetic results authentication or trust.

## Closed source model and API

The exact native source model has four keys:

```json
{
  "schema_version": 1,
  "source_id": "synthetic-saml-conditions",
  "assertion_xml_base64": "<canonical base64 of exact UTF-8 XML bytes>",
  "evaluation_context": {
    "evaluated_at_utc": "2026-09-29T12:00:00Z",
    "audience": "https://service.invalid/sp"
  }
}
```

`analyze_supplied_saml_conditions(model)` and
`analyze_supplied_saml_conditions_bytes(*, model_bytes)` create an immutable
`SamlConditionsAnalysis`. `from_dict`, `from_json`, `to_dict`, and `to_json`
replay the embedded original source. `verify_supplied_saml_conditions_analysis`
also requires a separately supplied original model. The report retains the
complete source model, exact XML-byte SHA-256, the source-model address,
condition rows, and a content-addressed result. Export alone is not
current-source verification. `component_fixture()` returns fresh synthetic
data without an address or other authority.

The supplied instant is not a read of the current clock. The audience is a
caller-declared exact URI identity; there is no URI normalization, metadata
lookup, or membership attestation. Supported time lexicals are bounded UTC
`YYYY-MM-DDTHH:MM:SS[.1-9 digits]Z`; unsupported source lexicals are
indeterminate. An unsupported supplied evaluation instant is refused. The
closed URI subset is bounded printable ASCII absolute references. A direct
SAML 2.0 `Assertion` and at most one direct `Conditions` are required. An
absent `Conditions` element is reported separately as unassessed. Unknown
conditions, attributes, or non-whitespace condition content remain
indeterminate. An explicit unknown condition never becomes a clean pass.
Other assertion content may be present but is not evaluated. XML DTD, entity
declarations, comments, and CDATA are refused by this closed parser subset;
there is no external entity resolution. UTF-16/NUL input and declarations
for encodings other than UTF-8 are refused. A simple XML 1.0 declaration
with an optional UTF-8 encoding declaration is accepted. This does not
claim complete XML or SAML schema validation.

## Software-cost bounds

The per-document bounds are XML 131,072 bytes, source model 262,144 canonical
bytes, report 524,288 canonical bytes, 4,096 source native nodes, 8,192
report native nodes, 4,096 XML elements, XML depth 32, native depth 16, and
256 aggregate audience entries/restrictions. One complete public operation
has a 33,554,432-unit cumulative software-work ceiling. These limits are
local software costs, not SAML authority or acceptance rules. Independent
maxima are not promised to fit simultaneously. The parser bounds input bytes
before decoding XML and refuses DTD/entity constructs. Each public operation
charges its complete model/report capture, XML parse, reconstruction,
serialization, equality and export work before its first digest. Separate
original verification derives both source plans under the same operation
work ceiling. Cost refusal never means a supplied assertion was invalid.

## Explicit exclusions

No XML Signature is verified. Issuer trust, assertion ID uniqueness, subject
confirmation, recipient, request correlation, protocol status, encrypted
content, OneTimeUse and ProxyRestriction behavior, replay consumption, clock
currentness, login, authorization, or live relying-party behavior is
established. Even condition validity does not establish that an assertion is
well-formed under the full schema, signed, trustworthy, or usable in a SAML
profile. The component has no target, provider, execution, routing,
deployment, or qualification effects.
