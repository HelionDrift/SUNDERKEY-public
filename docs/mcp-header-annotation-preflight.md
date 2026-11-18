# MCP header annotation preflight

`mcp-header-annotation-preflight` verifies the exact schema-byte and Draft
2020-12 semantic preflight results before reviewing static `x-mcp-header`
annotations for the pinned MCP `2026-07-28` revision. It accepts only
nonempty HTTP token names that are case-insensitively unique within a tool.
An annotation must appear on a string, boolean, or integer input property
reachable through a chain of `properties` keys from the schema root.
Annotations at the root, in output schemas, or behind arrays, composition,
conditionals, or references fail closed.

The result records each header name and exact property path. A bounded
integer schema can prove that all accepted values fit the JavaScript safe
integer range. Otherwise the result explicitly requires a runtime integer
range check. It does not validate any concrete tool arguments, encode HTTP
header values, resolve schema references, compare headers with request-body
values, authenticate a caller, or serve a tool.

```sh
python -m sunderkey.cli mcp-header-annotation-preflight \
  --manifest proposed-mcp-catalog.json \
  --preflight mcp-preflight.json \
  --schemas proposed-mcp-schemas.json \
  --byte-result mcp-schema-byte-result.json \
  --semantic-result mcp-schema-semantic-result.json > mcp-header-result.json

python -m sunderkey.cli mcp-header-annotation-preflight-verify \
  --manifest proposed-mcp-catalog.json \
  --preflight mcp-preflight.json \
  --schemas proposed-mcp-schemas.json \
  --byte-result mcp-schema-byte-result.json \
  --semantic-result mcp-schema-semantic-result.json \
  --result mcp-header-result.json
```

The static rules follow the pinned [MCP Streamable HTTP specification](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http).
This packet has no network, authorization, tool, target, or qualification
effect. A deployed client and server must still enforce the protocol's
value encoding and header-to-body parity rules independently.
The separate [header value codec](mcp-header-value-codec.md) rehearses those
value rules in memory, without proving deployed behavior.
