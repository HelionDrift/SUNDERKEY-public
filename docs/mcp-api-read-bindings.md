# MCP read-tool to API binding plan

The `mcp-api-read-bindings` command maps a complete proposed MCP read-tool
catalog to SUNDERKEY's closed external API operation vocabulary. It first
reproduces the [MCP catalog preflight](mcp-catalog-preflight.md) from the exact
manifest and requires zero declared control gaps. Action-class tools are not
permitted in this plan.

Source preflight and output plan reproduction preserve exact JSON types.
Changing a count or version from an integer to a Boolean or float cannot pass
verification or feed a downstream plan under an unchanged digest. Binding
requests and plans reject non-JSON containers and values, nonfinite numbers,
cycles, more than 24 nesting levels, more than 100,000 nodes, and more than
1,000,000 canonical bytes. Key order is immaterial and valid digests are stable.

Only these exact mappings are accepted:

| MCP tool name | SUNDERKEY API operation |
| --- | --- |
| `sunderkey.get_status` | `get_status` |
| `sunderkey.list_evidence` | `list_evidence` |
| `sunderkey.list_findings` | `list_findings` |
| `sunderkey.get_report` | `get_report` |

The request has `schema_version: 1` and a `bindings` list with one
`tool_name` and `api_operation` pair for every declared tool, in exact catalog
order. The result binds the manifest, preflight, request, current API
operation vocabulary, tenant, scope, and server reference. It can be
reproduced without starting a server:

```sh
python -m sunderkey.cli mcp-api-read-bindings \
  --manifest proposed-mcp-catalog.json \
  --preflight mcp-preflight.json \
  --bindings read-bindings.json > read-binding-plan.json

python -m sunderkey.cli mcp-api-read-bindings-verify \
  --manifest proposed-mcp-catalog.json \
  --preflight mcp-preflight.json \
  --bindings read-bindings.json \
  --plan read-binding-plan.json
```

This plan does not expose a live MCP tool, call the API, authenticate a
principal, evaluate returned data, or grant authority. The separate
[schema-byte preflight](mcp-schema-byte-preflight.md) can check the exact
caller-supplied bytes behind the catalog's asserted digests, but neither
artifact proves deployed server behavior. A future implementation must enforce
per-request identity, tenant and scope filters, live authorization, output
redaction, rate limits, audit custody, and protocol conformance before any
read can be exposed. Mutating API operations require a separate design and
independent action admission, not a name change in this map.
