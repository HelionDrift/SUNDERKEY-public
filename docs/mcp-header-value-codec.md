# MCP parameter-header value codec

`sunderkey.mcp_header_value_codec` provides pure, in-memory helpers for the
pinned MCP `2026-07-28` Streamable HTTP parameter-header format. It encodes
strings, booleans, and safe integers. Plain visible ASCII is used where safe;
UTF-8 Base64 sentinel encoding is used for non-ASCII text, control characters,
leading or trailing whitespace, empty strings, and values that already match
the sentinel pattern. Values are limited to 8,192 UTF-8 bytes as a local
resource bound.

`decode_mcp_parameter_header_value` rejects unsafe plain headers, malformed
or noncanonical Base64, invalid UTF-8, wrong primitive types, and integers
outside the JavaScript safe range. Its integer decoding permits numeric
comparison of a decimal header such as `42.0` with a JSON integer value of
`42`. `check_mcp_parameter_header_body_parity` follows one validated
annotation's property path and checks a caller-supplied header against a
caller-supplied arguments object. A missing or null property requires the
header to be omitted. It returns only a status and presence flags, not the
value or header text.

These helpers do not open an HTTP connection, construct a request, validate
the identity or authority of a caller, or prove that an actual client and
server enforce header parity. A caller must first verify the exact
[header annotation preflight](mcp-header-annotation-preflight.md). The
[MCP Streamable HTTP specification](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http)
defines the wire rules. This local codec does not confer target, tool,
network, authorization, or qualification authority.
