# Offline MCP Local Reference Closure

This V9.15 companion checks whether every local JSON Pointer reference in the
caller-supplied MCP tool schemas points to a recognized schema location. It
replays the existing catalog, exact schema-byte, and Draft 2020-12 semantic
preflights first. No schema is fetched from a network location, and no MCP
server or tool is started.

## Bounded Check

The checker walks schema-bearing keywords, including `$defs`, properties,
composition branches, and dependent schemas. It checks local `#` and `#/...`
references, including `~0` and `~1` pointer escapes. A target must exist and
be a schema location, not a similarly shaped object inside `const` or other
literal data. It rejects missing targets, external and percent-encoded
references, named or dynamic anchors, and nested `$id` base changes. It does
not recursively evaluate a referenced schema, so cycles are not expanded.
The report is source-bound and reproducible under
[`mcp-local-reference-closure-v1.schema.json`](../registry/schemas/mcp-local-reference-closure-v1.schema.json).

## Local API

`build_mcp_local_reference_closure` accepts the exact five source objects:
catalog manifest, catalog preflight, schema byte bundle, byte preflight, and
semantic preflight. `verify_mcp_local_reference_closure` accepts the same
sources plus the report and reproduces it. Both functions are local and
non-authorizing. A CLI wrapper is deferred until the repository's hash-bound
CLI evidence catalogs can be updated together.

## Safety Boundary

Target presence does not prove that a JSON Schema accepts or rejects any
particular argument. This is not full JSON Schema evaluation or proof of a
deployed MCP server's behavior. It does not authenticate a principal, grant
scope, publish a catalog, authorize an action, execute a tool, or interact
with a target. External references and richer URI or dynamic-scope semantics
remain unresolved until separately designed and reviewed.
