# Offline MCP Read Tool List Preview

This V9.15 companion builds an inert `tools/list` result-shape preview from
the source-replayed [read-tool closure](mcp-read-tool-closure.md). It contains
the proposed tool names and exact caller-supplied input and output schemas.
The module neither opens an MCP server nor returns a result to a client.

The proposed list is complete and deterministically ordered by the validated
catalog. It uses `ttlMs: 0` and `cacheScope: private` because the catalog
declares principal-scoped visibility. The pinned MCP
[tool-list specification](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)
requires a complete result with tools, while its
[caching specification](https://modelcontextprotocol.io/specification/2026-07-28/server/utilities/caching)
requires caching hints on complete `tools/list` results. These source-shape
checks do not prove that a deployed server returns the preview, applies
per-request authorization, or isolates one caller's tool list from another.

`build_mcp_read_tool_list_preview` consumes the same nine sources as the
read-tool closure plus that closure. Its verifier reproduces the exact result.
The closed schema is
[`mcp-read-tool-list-preview-v1.schema.json`](../registry/schemas/mcp-read-tool-list-preview-v1.schema.json).
The preview includes schema content rather than only digests, so operators
must not supply sensitive schema descriptions or publish it without a separate
content review. No principal is authenticated, no tenant filter is enforced,
no tool is served, no API is called, and no target is contacted by this module.
The preview does not establish how tool arguments or results map to the API.
Its output is not a release gate or qualification evidence.
