# MCP schema semantic preflight

`mcp-schema-semantic-preflight` first verifies the exact schema-byte result,
then checks each supplied tool schema against the Draft 2020-12 metaschema.
For the pinned MCP `2026-07-28` revision, an input schema must declare an
object root. An output schema may be an object or boolean JSON Schema. The
preflight accepts composition, conditional keywords, and references where
the metaschema allows them. It rejects unsupported `$schema` dialects and
schemas exceeding 64 structural levels or 10,000 JSON nodes.

Structural bounds cover every JSON value, including literal and extension
metadata. Dialect and reference inspection is separate: it visits only actual
schema positions in the pinned Draft 2020-12 vocabulary. Supported positions
include schema maps, single subschemas, composition arrays and the deprecated
`definitions` and schema-valued `dependencies` entries retained by the pinned
metaschema. Property names such as `$schema` or `$ref` are not keywords in their
map container. Values under `const`, `enum`, `default`, `examples`, unknown
extensions and property-name dependency arrays remain ordinary bounded data.
Their contents cannot change dialect checks or reference counts.

Actual unsupported dialects and invalid nested schema keywords still fail.
Reference counts retain the existing lexical classification: a reference
starting with `#` is local; every other reference is counted as external.
No resolution or existence check is performed. Valid prior summaries retain
their hashes. A prior false-positive summary that counted literal data as a
reference no longer reproduces, even if its own content hash is intact.

The result is content-addressed and contains no raw schema bytes. It records
reference counts, including external references, but resolves none of them.
An external reference may therefore be metaschema-valid without being
available or safe to evaluate. This is a structural check only. It does not
validate sample arguments or results. The separate
[header annotation preflight](mcp-header-annotation-preflight.md) checks static
`x-mcp-header` declarations but not HTTP request behavior. This preflight does
not authenticate a server or prove runtime schema parity or enforcement.

```sh
python -m sunderkey.cli mcp-schema-semantic-preflight \
  --manifest proposed-mcp-catalog.json \
  --preflight mcp-preflight.json \
  --schemas proposed-mcp-schemas.json \
  --byte-result mcp-schema-byte-result.json > mcp-schema-semantic-result.json

python -m sunderkey.cli mcp-schema-semantic-preflight-verify \
  --manifest proposed-mcp-catalog.json \
  --preflight mcp-preflight.json \
  --schemas proposed-mcp-schemas.json \
  --byte-result mcp-schema-byte-result.json \
  --result mcp-schema-semantic-result.json
```

The pinned [MCP tools specification](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)
defines the tool-schema boundary. This local preflight grants no tool,
target, network, authorization, or qualification effect. Live use still
requires authenticated identity, current scope, confirmation, admission,
redaction, audit, and deployment checks.
