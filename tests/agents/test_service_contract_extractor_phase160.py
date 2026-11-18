"""Phase 160 strict offline service contract extraction tests."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

from sunderkey.qualification import _canonical_sha256
from sunderkey.service_contract_extractor import (
    BUNDLE_DOMAIN,
    ENDPOINT_DOMAIN,
    ServiceContractEndpointBundle,
    ServiceContractExtractionError,
    ServiceContractExtractionLimits,
    extract_service_contract_endpoints,
)

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = ROOT / "registry" / "schemas" / "service-contract-endpoint-bundle-v1.schema.json"


class ServiceContractExtractorPhase160Tests(unittest.TestCase):
    def test_openapi_json_extracts_servers_methods_and_effective_security(self) -> None:
        content = json.dumps(
            {
                "openapi": "3.1.1",
                "servers": [{"url": "https://API.EXAMPLE.test/v1?region=west#ignored"}],
                "security": [{"oauth": ["write", "read"]}],
                "paths": {
                    "/pets/{petId}": {
                        "get": {"operationId": "getPet"},
                        "post": {
                            "operationId": "replacePet",
                            "servers": [{"url": "/preview"}],
                            "security": [{"api_key": []}],
                            "examples": {"credential": "example-secret-must-not-persist"},
                        },
                    }
                },
            },
            separators=(",", ":"),
        ).encode()

        first = extract_service_contract_endpoints(
            content,
            source_id="artifact-17",
            provenance={"artifact_id": "INGEST-17", "collector": "local-fixture"},
        )
        second = extract_service_contract_endpoints(
            content,
            source_id="artifact-17",
            provenance={"collector": "local-fixture", "artifact_id": "INGEST-17"},
        )

        self.assertEqual(first.to_dict(), second.to_dict())
        self.assertEqual(first.document_kind, "openapi")
        self.assertEqual(first.document_version, "3.1.1")
        self.assertEqual(first.source["byte_size"], len(content))
        self.assertEqual(len(first.endpoints), 2)
        get_endpoint = next(item for item in first.endpoints if item.method == "GET")
        post_endpoint = next(item for item in first.endpoints if item.method == "POST")
        self.assertEqual(get_endpoint.address, "https://api.example.test/v1/pets/{petId}")
        self.assertEqual(
            get_endpoint.security_requirements,
            ({"schemes": [{"name": "oauth", "scopes": ["read", "write"]}]},),
        )
        self.assertEqual(post_endpoint.address, "/preview/pets/{petId}")
        self.assertNotIn("example-secret", json.dumps(first.to_dict()))
        self.assertEqual(
            ServiceContractEndpointBundle.from_dict(first.to_dict(), content=content), first
        )

    def test_safe_yaml_and_swagger_2_extraction(self) -> None:
        content = b"""swagger: '2.0'
host: api.example.test
basePath: /v2
schemes: [https, http]
security:
  - api_key: []
paths:
  /widgets:
    get:
      operationId: listWidgets
"""
        bundle = extract_service_contract_endpoints(content, source_name="swagger-fixture")
        self.assertEqual(bundle.document_kind, "swagger")
        self.assertEqual(bundle.document_version, "2.0")
        self.assertEqual(
            [item.address for item in bundle.endpoints],
            ["http://api.example.test/v2/widgets", "https://api.example.test/v2/widgets"],
        )
        self.assertTrue(all(item.operation_id == "listWidgets" for item in bundle.endpoints))
        self.assertTrue(all(item.security_requirements for item in bundle.endpoints))

    def test_wsdl_extracts_service_port_binding_operation_and_address(self) -> None:
        content = b"""<?xml version="1.0"?>
<definitions xmlns="http://schemas.xmlsoap.org/wsdl/"
 xmlns:tns="urn:catalog" xmlns:soap12="http://schemas.xmlsoap.org/wsdl/soap12/">
  <binding name="CatalogBinding" type="tns:CatalogPortType">
    <soap12:binding transport="http://schemas.xmlsoap.org/soap/http"/>
    <operation name="Lookup"><soap12:operation soapAction="urn:catalog:lookup"/></operation>
  </binding>
  <service name="CatalogService">
    <port name="CatalogPort" binding="tns:CatalogBinding">
      <soap12:address location="https://catalog.example.test/soap?trace=ignored"/>
    </port>
  </service>
</definitions>
"""
        bundle = extract_service_contract_endpoints(content, source_id="wsdl-fixture")
        self.assertEqual(bundle.document_kind, "wsdl")
        self.assertEqual(bundle.document_version, "1.1")
        self.assertEqual(len(bundle.endpoints), 1)
        endpoint = bundle.endpoints[0]
        self.assertEqual(endpoint.transport, "soap12")
        self.assertEqual(endpoint.address, "https://catalog.example.test/soap")
        self.assertEqual(endpoint.service, "CatalogService")
        self.assertEqual(endpoint.port, "CatalogPort")
        self.assertEqual(endpoint.binding, "CatalogBinding")
        self.assertEqual(endpoint.operation_id, "Lookup")
        self.assertEqual(endpoint.soap_action, "urn:catalog:lookup")

    def test_valid_empty_document_is_distinct_from_parse_error(self) -> None:
        valid = b'{"openapi":"3.0.3","paths":{}}'
        bundle = extract_service_contract_endpoints(valid)
        self.assertEqual(bundle.extraction_status, "complete_empty")
        self.assertEqual(bundle.endpoints, ())
        with self.assertRaisesRegex(ServiceContractExtractionError, "content is empty"):
            extract_service_contract_endpoints(b" \n")
        with self.assertRaisesRegex(ServiceContractExtractionError, "JSON is invalid"):
            extract_service_contract_endpoints(b'{"openapi":')

    def test_hard_byte_depth_item_string_and_endpoint_limits(self) -> None:
        with self.assertRaisesRegex(ServiceContractExtractionError, "byte limit"):
            extract_service_contract_endpoints(
                b'{"openapi":"3.0.0","paths":{}}',
                limits=ServiceContractExtractionLimits(max_bytes=8),
            )
        deep: object = "leaf"
        for _ in range(10):
            deep = {"node": deep}
        with self.assertRaisesRegex(ServiceContractExtractionError, "nesting depth"):
            extract_service_contract_endpoints(
                json.dumps({"openapi": "3.0.0", "paths": {}, "deep": deep}),
                limits=ServiceContractExtractionLimits(max_depth=6),
            )
        with self.assertRaisesRegex(ServiceContractExtractionError, "item limit"):
            extract_service_contract_endpoints(
                json.dumps({"openapi": "3.0.0", "paths": {}, "many": list(range(20))}),
                limits=ServiceContractExtractionLimits(max_items=8),
            )
        with self.assertRaisesRegex(ServiceContractExtractionError, "string limit"):
            extract_service_contract_endpoints(
                json.dumps({"openapi": "3.0.0", "paths": {}, "long": "x" * 20}),
                limits=ServiceContractExtractionLimits(max_string_length=8),
            )
        with self.assertRaisesRegex(ServiceContractExtractionError, "endpoint limit"):
            extract_service_contract_endpoints(
                json.dumps(
                    {
                        "openapi": "3.0.0",
                        "paths": {"/a": {"get": {}}, "/b": {"get": {}}},
                    }
                ),
                limits=ServiceContractExtractionLimits(max_endpoints=1),
            )

    def test_parser_bombs_and_duplicate_keys_fail_closed(self) -> None:
        with self.assertRaisesRegex(ServiceContractExtractionError, "Duplicate JSON key"):
            extract_service_contract_endpoints(b'{"openapi":"3.0.0","openapi":"3.1.0","paths":{}}')
        with self.assertRaisesRegex(ServiceContractExtractionError, "Duplicate YAML key"):
            extract_service_contract_endpoints(b"openapi: 3.0.0\npaths: {}\npaths: {}\n")
        with self.assertRaisesRegex(ServiceContractExtractionError, "anchors, aliases"):
            extract_service_contract_endpoints(
                b"openapi: 3.0.0\npaths: &shared {}\ncomponents: *shared\n"
            )
        xml_bomb = b'<!DOCTYPE x [<!ENTITY a "123">]><x>&a;</x>'
        with self.assertRaisesRegex(ServiceContractExtractionError, "DTD and entity"):
            extract_service_contract_endpoints(xml_bomb)
        xinclude = (
            b'<definitions xmlns="http://schemas.xmlsoap.org/wsdl/" '
            b'xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///x"/></definitions>'
        )
        with self.assertRaisesRegex(ServiceContractExtractionError, "XInclude"):
            extract_service_contract_endpoints(xinclude)

    def test_external_and_traversal_references_are_rejected(self) -> None:
        for reference in (
            "https://example.test/common.yaml#/Thing",
            "../common.yaml#/Thing",
            "%2e%2e/common.yaml#/Thing",
            "file:///tmp/common.yaml#/Thing",
        ):
            with self.subTest(reference=reference):
                content = json.dumps(
                    {
                        "openapi": "3.0.0",
                        "paths": {"/pets": {"$ref": reference}},
                    }
                )
                with self.assertRaisesRegex(ServiceContractExtractionError, "reference|traversal"):
                    extract_service_contract_endpoints(content)
        wsdl_import = b"""<definitions xmlns="http://schemas.xmlsoap.org/wsdl/">
<import namespace="urn:other" location="../other.wsdl"/>
</definitions>"""
        with self.assertRaisesRegex(ServiceContractExtractionError, "WSDL references"):
            extract_service_contract_endpoints(wsdl_import)

    def test_local_path_reference_is_resolved_without_external_access(self) -> None:
        content = json.dumps(
            {
                "openapi": "3.1.0",
                "paths": {"/status": {"$ref": "#/components/pathItems/Status"}},
                "components": {"pathItems": {"Status": {"get": {"operationId": "getStatus"}}}},
            }
        )
        bundle = extract_service_contract_endpoints(content)
        self.assertEqual(len(bundle.endpoints), 1)
        self.assertEqual(bundle.endpoints[0].address, "/status")
        self.assertEqual(bundle.endpoints[0].operation_id, "getStatus")

    def test_secret_bearing_endpoint_and_provenance_fields_are_rejected(self) -> None:
        for server in (
            "https://user:password@example.test/v1",
            "https://example.test/v1?api_key=example-secret",
        ):
            with self.subTest(server=server):
                content = json.dumps(
                    {
                        "openapi": "3.0.0",
                        "servers": [{"url": server}],
                        "paths": {"/pets": {"get": {}}},
                    }
                )
                with self.assertRaisesRegex(ServiceContractExtractionError, "credential"):
                    extract_service_contract_endpoints(content)
        with self.assertRaisesRegex(ServiceContractExtractionError, "provenance field"):
            extract_service_contract_endpoints(
                b'{"openapi":"3.0.0","paths":{}}',
                provenance={"access_token": "example-secret"},
            )

    def test_tampering_and_noncanonical_order_are_rejected(self) -> None:
        content = json.dumps(
            {
                "openapi": "3.0.0",
                "paths": {"/z": {"get": {}}, "/a": {"post": {}}},
            }
        )
        bundle = extract_service_contract_endpoints(content)
        changed = copy.deepcopy(bundle.to_dict())
        changed["endpoints"][0]["path"] = "/substituted"
        with self.assertRaisesRegex(ServiceContractExtractionError, "endpoint|Endpoint"):
            ServiceContractEndpointBundle.from_dict(changed)

        reordered = copy.deepcopy(bundle.to_dict())
        reordered["endpoints"].reverse()
        with self.assertRaisesRegex(ServiceContractExtractionError, "canonical order"):
            ServiceContractEndpointBundle.from_dict(reordered)

        changed_source = copy.deepcopy(bundle.to_dict())
        changed_source["source"]["source_id"] = "substituted"
        with self.assertRaisesRegex(ServiceContractExtractionError, "identity"):
            ServiceContractEndpointBundle.from_dict(changed_source)

        with self.assertRaisesRegex(ServiceContractExtractionError, "source content"):
            ServiceContractEndpointBundle.from_dict(bundle.to_dict(), content=b"different")

        rehashed = copy.deepcopy(bundle.to_dict())
        endpoint = rehashed["endpoints"][0]
        endpoint["address"] = "https://user:password@example.test/a"
        endpoint_body = {key: value for key, value in endpoint.items() if key != "endpoint_sha256"}
        endpoint["endpoint_sha256"] = _canonical_sha256(
            {"domain": ENDPOINT_DOMAIN, "endpoint": endpoint_body}
        )
        bundle_body = {
            key: value
            for key, value in rehashed.items()
            if key not in {"bundle_id", "bundle_sha256"}
        }
        rehashed["bundle_sha256"] = _canonical_sha256(
            {"domain": BUNDLE_DOMAIN, "bundle": bundle_body}
        )
        rehashed["bundle_id"] = (
            "SCEB-" + rehashed["bundle_sha256"].removeprefix("sha256:")[:32].upper()
        )
        with self.assertRaisesRegex(ServiceContractExtractionError, "credentials"):
            ServiceContractEndpointBundle.from_dict(rehashed)

    def test_unsupported_versions_and_media_types_are_rejected(self) -> None:
        for content in (
            b'{"openapi":"2.0","paths":{}}',
            b'{"swagger":"3.0","paths":{}}',
            b'<description xmlns="urn:not-wsdl"/>',
        ):
            with (
                self.subTest(content=content),
                self.assertRaisesRegex(ServiceContractExtractionError, "Unsupported"),
            ):
                extract_service_contract_endpoints(content)
        with self.assertRaisesRegex(ServiceContractExtractionError, "media type"):
            extract_service_contract_endpoints(
                b"openapi: 3.0.0\npaths: {}\n", media_type="application/octet-stream"
            )

    @unittest.skipUnless(Draft202012Validator is not None, "jsonschema is not installed")
    def test_bundle_matches_json_schema(self) -> None:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        bundle = extract_service_contract_endpoints(
            b'{"openapi":"3.0.3","paths":{"/health":{"get":{}}}}'
        )
        Draft202012Validator(schema).validate(bundle.to_dict())


if __name__ == "__main__":
    unittest.main()
