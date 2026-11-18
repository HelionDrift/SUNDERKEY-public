# Supplied JSON Key Policy Differential

The `AOE-GE-D23-S04` partial specialist compares first-occurrence and
last-occurrence interpretations of duplicate field names in a caller-supplied
flat JSON object. It preserves decoded field order before applying either
finite local policy. Escaped spellings that decode to the same field name are
treated as the same key. A `candidate_first_last_difference` label means only
that these two local interpretations select different endpoint values.

The exact native model declares `schema_version: 1`,
`semantics_profile: supplied-flat-json-key-policies-v1`, an opaque source ID,
and up to 8 KiB of JSON text. At most 256 fields are accepted. Values are
bounded strings, signed 64-bit integers, booleans, or null. Nested values,
floating-point numbers, nonfinite numbers, over-budget text, resource fields,
and malformed JSON are refused. The report embeds the original text and
requires exact source replay for verification.

This finite model does not establish which policy any target parser uses. It
does not parse files, evaluate an application, prove a polyglot or security
impact, or grant action authority. There is no file access, network call,
credential use, target interaction, finding publication, or qualification.
The [synthetic example](../examples/offline-json-key-policy-component.json)
uses only supplied text.
