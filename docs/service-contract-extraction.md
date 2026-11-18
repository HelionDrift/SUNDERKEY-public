# Offline Service Contract Endpoint Extraction

## Purpose

`src/sunderkey/service_contract_extractor.py` turns already-ingested OpenAPI 3.x, Swagger 2.0, and WSDL documents into deterministic endpoint records. It performs no file reads, network requests, reference resolution, DNS lookup, authentication, or target interaction.

Call `extract_service_contract_endpoints` with bytes or already-ingested text. The caller supplies a stable `source_id` and may supply non-secret provenance strings. The result is a `ServiceContractEndpointBundle`.

## Supported inputs

- OpenAPI 3.x in JSON or the supported safe YAML subset.
- Swagger 2.0 in JSON or the supported safe YAML subset.
- WSDL 1.1 and WSDL 2.0 XML with SOAP endpoint declarations.

OpenAPI records include effective document, path, or operation servers; paths; HTTP methods; operation identifiers; and effective security requirements. Swagger records include schemes, host, base path, paths, methods, operation identifiers, and effective security requirements. WSDL records include services, ports or endpoints, bindings, operations, SOAP actions, addresses, and SOAP version.

A valid contract with no discovered operations returns `extraction_status` set to `complete_empty`. Empty bytes, malformed input, unsupported versions, and unsafe constructs raise `ServiceContractExtractionError`. This keeps an extraction failure distinct from a valid zero-endpoint result.

## Parsing boundary

The default ceilings are 2 MiB of input, 64 levels of nesting, 100,000 parsed items, 16,384 characters per string, and 10,000 endpoint records. `ServiceContractExtractionLimits` permits lower positive ceilings for a controlled caller. Every ceiling is fail-closed.

JSON parsing rejects duplicate object keys and non-finite numbers. YAML parsing rejects duplicate mapping keys, anchors, aliases, tags, merge keys, directives, non-finite numbers, and malformed indentation. XML parsing rejects DTD declarations, entity declarations, XInclude, WSDL imports, XML Schema includes or imports, excessive depth, excessive item counts, and excessive text or attribute lengths.

Only local JSON Pointer `$ref` values are accepted. External, file, network, backslash, encoded traversal, and parent traversal references are rejected. Local path-item references are resolved inside the already-parsed document with cycle and depth checks. Resolution never reads another file or contacts a URL.

## Secret handling

The bundle does not copy request examples, response examples, schema examples, security scheme definitions, server variable defaults, arbitrary descriptions, or extension values. Security requirements preserve only scheme names and scope names.

Endpoint URLs reject user information, unsupported schemes, traversal components, and credential-like query fields. Query strings and fragments are not persisted. Provenance keys that indicate passwords, tokens, API keys, authorization data, cookies, secrets, or credentials are rejected.

## Content addressing and provenance

Each bundle source record contains the caller's source identifier, media type, byte size, raw content SHA-256 digest, and canonical non-secret provenance. Each endpoint has its own canonical SHA-256 digest. The bundle digest covers the complete bundle body under the `sunderkey.service-contract-endpoint-bundle.v1` domain, and the `SCEB-` identifier is derived from that digest.

`ServiceContractEndpoint.from_dict` verifies exact fields, normalized security structure, and the endpoint digest. `ServiceContractEndpointBundle.from_dict` verifies exact fields, versions, endpoint hashes, canonical ordering, uniqueness, counts, status, authority controls, bundle digest, and bundle identifier. If original content is supplied to `from_dict`, it also verifies byte size and raw content digest.

The JSON Schema contract is `registry/schemas/service-contract-endpoint-bundle-v1.schema.json`.

## Authority boundary

Every bundle fixes `offline_only` to `true` and `target_authority_effect` to `none`. Endpoint strings are passive observations from caller-supplied content. They are not approved targets, scope grants, credentials, routes, execution plans, or permission to make a live request.
