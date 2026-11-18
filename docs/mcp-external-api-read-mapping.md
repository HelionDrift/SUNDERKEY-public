# Offline MCP External API Read Mapping

This V9.15 follow-on maps the four curated MCP read-tool names to the
existing [external API contract](api-service-contracts.md). It is a pure
offline projection, not an MCP server or a service adapter. No API call,
network request, tool execution, or target interaction occurs.

| MCP Tool | External API Operation | Arguments |
| --- | --- | --- |
| `sunderkey.get_status` | `get_status` | `resource_id` |
| `sunderkey.list_evidence` | `list_evidence` | `resource_id`, `page_size`, optional `cursor` |
| `sunderkey.list_findings` | `list_findings` | `resource_id`, `page_size`, optional `cursor` |
| `sunderkey.get_report` | `get_report` | `resource_id` |

The argument and structured-output profiles are closed JSON Schemas. A
schema-level check mirrors the API identifier, cursor, digest, resource-kind,
resource-version, error-code, page-count, and 1,000-reference limits. The
runtime contract remains authoritative if a schema consumer behaves
differently. A projection first replays the exact nine-source
[read-tool list preview](mcp-read-tool-list-preview.md) and its closure, then
requires the selected tool to carry the expected operation and schemas.
Unknown tools, extra arguments, substituted schemas, cross-tenant context,
and API responses that do not match the request fail closed. A list operation
also requires an explicit page size within the external API budget. Empty
successful list pages remain valid.

The optional `tools/call` params projector accepts exactly `name` and
`arguments`. It rejects caller-provided binding, token, or `_meta` fields;
the separate JSON-RPC projector checks a narrow per-request metadata profile
and strips it before using this lower-level mapper. Neither function claims
to implement the entire MCP protocol.

The caller supplies a typed `TenantPrincipalBinding`, `RequestBudget`,
`request_id`, and `issued_at` from a future trusted host. The MCP caller
cannot set these fields through tool arguments. The returned
`ApiRequestEnvelope` is only an untrusted candidate. Its construction does
not authenticate the host, validate the principal or audience, prove current
scope, enforce tenant visibility, or grant action authority. A production
host must perform those checks independently for each positive use before
calling the external API, including fresh request identity and replay
protection. No stored preview or historical proof replaces
live-currentness checks.

Given an already supplied `ApiResponseEnvelope`, the reverse projection
verifies its exact API request binding and budgets before producing an MCP
`tools/call`-shaped result with `content`, `structuredContent`, and `isError`.
Both typed API inputs are reconstructed before projection so that later
mutation of a previously valid object cannot retain its original address.
The result declares `resultType: "complete"` for both successful reads and
tool-level rejections. It never requests another input round trip.
The structured result contains only status, resource references, pagination,
and a stable error code with retryability. It omits principal bindings,
authentication context, error messages, and error detail references. The
plain-text content is the canonical JSON form of the same structured result.
The combined exchange projector reconstructs the candidate request from the
exact `tools/call` parameters and trusted-host inputs before accepting a
supplied response. A response for another resource, request identity, or
principal therefore cannot be projected as this call's result.
The complete result, including both text and structured copies, is bounded
to one million canonical JSON bytes.
This shape follows the pinned MCP
[tool-result specification](https://modelcontextprotocol.io/specification/2026-07-28/server/tools),
but the local projection does not prove interoperability with a deployed
client or server.

## Offline JSON-RPC Read Framing

`project_mcp_jsonrpc_read_request` accepts one bounded JSON-RPC 2.0
`tools/call` request with a non-null string or integer correlation ID. It
uses a canonical JSON snapshot so later caller mutation cannot change the
request being projected. It requires the pinned protocol revision and a
client-capabilities object in
`params._meta`, and accepts optional client info with bounded name and version
strings. The envelope,
params, and metadata keys are otherwise closed for this restricted read
profile. Unsupported extension metadata, input-required retries, and other
MCP methods need a separately designed host boundary. A valid client request
under the broader protocol can therefore be outside this local profile.

The client ID and metadata are never promoted to the trusted API `request_id`,
principal binding, budget, or authorization. The request projector returns
the client ID, selected tool name, and an untrusted API request candidate.
`project_mcp_jsonrpc_read_exchange` uses that candidate to replay a supplied
API response and wraps the complete tool result under the same client ID.
An API-level rejection remains a completed tool result with `isError: true`,
not a fabricated JSON-RPC protocol error. The full request is capped at
32,768 canonical JSON bytes, and the full response at one million bytes.
`project_mcp_jsonrpc_read_tool_list` applies the same envelope and metadata
checks to a `tools/list` request with no cursor. It replays the exact catalog
preview, checks each declared tool against its external API read binding and
schemas, and wraps the complete, private, immediately stale list result under
the client ID. It requires a typed host-supplied binding for the catalog
tenant, but that binding is not authenticated by this projection. The list
result is only an unserved candidate. A future host must authorize each
catalog disclosure using live current scope and tenant visibility. The
restricted no-cursor profile is not a general pagination implementation.
These checks follow the pinned MCP [base protocol](https://modelcontextprotocol.io/specification/2026-07-28/basic/index)
and [tool call](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)
shapes, but do not serve either message, validate transport headers, manage
in-flight ID uniqueness, authenticate clients, or demonstrate interoperability.

This work has no qualification effect. Before a live adapter is possible,
the trusted host must bind per-call identity, enforce authorization and
tenant filtering, validate current scope, meter budgets and rate limits,
restrict egress, audit requests and responses, and demonstrate the actual
MCP and external API exchange under separate approval.
