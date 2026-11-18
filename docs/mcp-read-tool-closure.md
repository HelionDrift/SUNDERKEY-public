# Offline MCP Read Tool Closure

The read-tool closure combines the existing V9.15 catalog, API read binding,
schema-byte, semantic, local-reference, and header-annotation checks into one
source-replayed review packet. It accepts only the four curated nonmutating API
operations. Every supplied intermediate result is reconstructed from the same
catalog and exact schema bytes before the packet is built.

The packet joins each tool name and API operation to its declared input and
output schema digests, local reference counts, and input header count. It does
not map tool arguments into an API request or API responses into tool results. It
contains no raw schema bytes, sample arguments, target data, or secrets. Its
content address binds all component result digests and the per-tool summary.
The closed output schema is
[`mcp-read-tool-closure-v1.schema.json`](../registry/schemas/mcp-read-tool-closure-v1.schema.json).

`build_mcp_read_tool_closure` accepts the catalog manifest, catalog preflight,
binding request and plan, schema bundle, byte preflight, semantic preflight,
local reference closure, and header preflight. The matching verifier rebuilds
the packet from all nine sources and rejects substituted sources or altered
claims. It does not fetch a reference, evaluate tool arguments against the
schema, authenticate a principal, apply tenant filtering, call an API, publish
an MCP catalog, start a server, or execute a tool.

This is a declaration consistency check, not a release gate or qualification.
Live MCP transport, server-presented schema equality, request and response
mapping, identity, scope, rate limiting, audit custody, and action admission
remain separate requirements.
