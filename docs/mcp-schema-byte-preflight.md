# MCP schema-byte preflight

`mcp-schema-byte-preflight` checks the schema data behind a proposed MCP
catalog's `input_schema_sha256` and `output_schema_sha256` declarations. It
first reproduces the exact [catalog preflight](mcp-catalog-preflight.md), then
requires one input and one output schema for every tool in catalog order.

The `--schemas` file is a bounded JSON object with `schema_version: 1` and a
`tools` list. Each item has exactly `tool_name`, `input_schema_base64`, and
`output_schema_base64`. The base64 values encode the exact UTF-8 JSON bytes of
the proposed schemas. An input value must be a JSON object; an output value
may be a JSON object or boolean schema. Duplicate keys and non-finite numbers
are rejected. Each decoded value is limited to
256,000 bytes, and the complete bundle is limited to 1,000,000 bytes.

The declared digest is `sha256:` followed by the lowercase SHA-256 hex digest
of the exact decoded bytes. Whitespace or key-order changes alter this digest,
even if the parsed schema is semantically equivalent. The result retains only
digests and byte counts, not schema content, and binds the catalog, preflight,
server, tenant, and scope references. It also carries the catalog's declared
control status, including any gaps, without treating a schema match as a
control pass.

```sh
python -m sunderkey.cli mcp-schema-byte-preflight \
  --manifest proposed-mcp-catalog.json \
  --preflight mcp-preflight.json \
  --schemas proposed-mcp-schemas.json > mcp-schema-byte-result.json

python -m sunderkey.cli mcp-schema-byte-preflight-verify \
  --manifest proposed-mcp-catalog.json \
  --preflight mcp-preflight.json \
  --schemas proposed-mcp-schemas.json \
  --result mcp-schema-byte-result.json
```

This is byte-integrity evidence for caller-supplied schemas, not JSON Schema
validation or proof that a server presents or enforces those schemas. Run the
separate [semantic preflight](mcp-schema-semantic-preflight.md) to check bounded
Draft 2020-12 metaschema validity and the MCP input root rule.
It does not authenticate the supplier, validate a token, expose a tool, call
the API, or authorize an action. The separate
[read-tool binding plan](mcp-api-read-bindings.md) remains a static operation
map. Any live MCP interface must independently verify deployed schema parity,
principal identity, current tenant and scope authority, output redaction,
rate limits, audit custody, and action admission.
