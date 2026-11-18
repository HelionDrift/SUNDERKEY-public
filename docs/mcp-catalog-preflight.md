# Governed MCP catalog preflight

`sunderkey.mcp_catalog_preflight` reviews a proposed tool catalog for the
[MCP 2026-07-28 protocol revision](https://modelcontextprotocol.io/specification/2026-07-28/server/tools).
It is a static, caller-declared policy check, not an MCP server. It does not
publish `tools/list`, accept `tools/call`, validate a token, contact a target,
or execute a tool.

The manifest binds an opaque server and tenant reference, a scope digest,
principal-scoped listing, disabled listing cache, and at most 64 sorted,
unique tools. Each tool declares its effect class, schema digests, rate
limit, and controls for authentication, token audience, tenant and scope
filtering, audit, human confirmation, and independent action admission. The
preflight flags missing controls, token passthrough, model self-authorization,
and reliance on untrusted tool annotations. An empty catalog is not a
completed declaration.

Manifest and preflight replay require exact JSON primitive types, rather than
Python's equality between Booleans, integers, and floats. Custom containers,
nonfinite numbers, cycles, and non-JSON values are rejected. Both artifacts
are bounded to 1,000,000 canonical bytes, 24 nesting levels, and 100,000 nodes.
Object key reordering is valid and existing valid preflight digests do not change.

```sh
python -m sunderkey.cli mcp-catalog-preflight \
  --manifest proposed-mcp-catalog.json > mcp-preflight.json
python -m sunderkey.cli mcp-catalog-preflight-verify \
  --manifest proposed-mcp-catalog.json --preflight mcp-preflight.json
```

The MCP specification allows model-controlled tools, recommends a human
denial path, and requires servers to validate access-token audience. Those
requirements are documented in the [tool specification](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)
and [authorization specification](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization).
This preflight checks only what the manifest asserts. It does not validate
JSON Schema bytes behind the supplied digests or prove that any declared
control is implemented. The separate
[schema-byte preflight](mcp-schema-byte-preflight.md) can check exact
caller-supplied bytes but still cannot prove server behavior. A
`declared_controls_complete_for_review` result
cannot authorize a model, user, or service to perform an action. Production
MCP needs authenticated transport, real token validation, tenant isolation,
live scope and action admission, audit custody, confirmation UX, rate limits,
and independent qualification.
