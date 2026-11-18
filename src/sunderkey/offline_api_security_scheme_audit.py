"""Audit referenced API security schemes against their local definitions."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from typing import Any
from urllib.parse import urlsplit

from .offline_api_security_matrix import (
    OfflineApiSecurityMatrixError,
    build_offline_api_security_matrix,
)
from .service_contract_extractor import (
    JSON_MEDIA_TYPES,
    ServiceContractEndpointBundle,
    ServiceContractExtractionError,
    ServiceContractExtractionLimits,
    _coerce_content,
    _parse_json,
    _parse_yaml,
    _resolve_local_mapping,
    extract_service_contract_endpoints,
)

DOMAIN = "sunderkey.offline-api-security-scheme-audit.v1"
MAX_DEFINITIONS = 256
NO_EFFECTS = {
    "authorization": "none",
    "credential_resolution": "none",
    "execution": "none",
    "finding_publication": "none",
    "network": "none",
    "qualification": "none",
    "target_interaction": "none",
}


class OfflineApiSecuritySchemeAuditError(ValueError):
    """Raised when a contract or its scheme audit cannot be checked safely."""


def _canonical(value: Any) -> str:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError, RecursionError) as exc:
        raise OfflineApiSecuritySchemeAuditError("audit input is not JSON data") from exc


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value).encode("ascii")).hexdigest()


def _definitions(document: Mapping[str, Any], kind: str) -> Mapping[str, Any]:
    if kind == "openapi":
        components = document.get("components", {})
        if not isinstance(components, dict):
            raise OfflineApiSecuritySchemeAuditError("OpenAPI components are invalid")
        definitions = components.get("securitySchemes", {})
    else:
        definitions = document.get("securityDefinitions", {})
    if not isinstance(definitions, dict) or len(definitions) > MAX_DEFINITIONS:
        raise OfflineApiSecuritySchemeAuditError("security scheme definitions are invalid")
    return definitions


def _url(value: Any) -> bool:
    if not isinstance(value, str) or not value or any(char.isspace() for char in value):
        return False
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        _ = parsed.port
    except ValueError:
        return False
    return (
        parsed.scheme in {"http", "https"}
        and bool(hostname)
        and parsed.username is None
        and parsed.password is None
    )


def _oauth_scopes(value: Any) -> bool:
    return isinstance(value, dict) and all(
        isinstance(name, str) and isinstance(description, str)
        for name, description in value.items()
    )


def _scheme_issues(
    *, name: str, scopes: Sequence[str], definition: Any,
    document: Mapping[str, Any], kind: str, openapi_minor: int | None,
) -> list[dict[str, str]]:
    if definition is None:
        return [{"code": "undefined_scheme", "scheme": name}]
    try:
        resolved = _resolve_local_mapping(
            dict(document), definition, f"security scheme {name}",
            ServiceContractExtractionLimits(),
        )
    except ServiceContractExtractionError:
        return [{"code": "invalid_scheme_reference", "scheme": name}]
    scheme_type = resolved.get("type")
    allowed = (
        {"apiKey", "http", "oauth2", "openIdConnect"}
        | ({"mutualTLS"} if openapi_minor is not None and openapi_minor >= 1 else set())
        if kind == "openapi" else {"apiKey", "basic", "oauth2"}
    )
    if not isinstance(scheme_type, str) or scheme_type not in allowed:
        return [{"code": "unsupported_scheme_type", "scheme": name}]
    issues = []
    if scheme_type == "apiKey":
        locations = {"header", "query", "cookie"} if kind == "openapi" else {
            "header", "query"
        }
        if (
            not isinstance(resolved.get("name"), str)
            or not resolved["name"].strip()
            or resolved.get("in") not in locations
        ):
            issues.append({"code": "incomplete_scheme_definition", "scheme": name})
    elif (
        scheme_type == "http" and (
            not isinstance(resolved.get("scheme"), str) or not resolved["scheme"].strip()
        )
    ) or (
        scheme_type == "openIdConnect" and not _url(resolved.get("openIdConnectUrl"))
    ):
        issues.append({"code": "incomplete_scheme_definition", "scheme": name})
    if scheme_type == "oauth2":
        if kind == "openapi":
            flows = resolved.get("flows")
            if not isinstance(flows, dict) or not flows:
                return [{"code": "incomplete_scheme_definition", "scheme": name}]
            required_by_flow = {
                "implicit": ("authorizationUrl",),
                "password": ("tokenUrl",),
                "clientCredentials": ("tokenUrl",),
                "authorizationCode": ("authorizationUrl", "tokenUrl"),
            }
            if openapi_minor is not None and openapi_minor >= 2:
                required_by_flow["deviceAuthorization"] = (
                    "deviceAuthorizationUrl", "tokenUrl"
                )
            supported_flows = {
                flow_name: flow for flow_name, flow in flows.items()
                if not isinstance(flow_name, str) or not flow_name.startswith("x-")
            }
            if not supported_flows or any(
                flow_name not in required_by_flow
                or not isinstance(flow, dict)
                or not _oauth_scopes(flow.get("scopes"))
                or any(not _url(flow.get(field)) for field in required_by_flow[flow_name])
                for flow_name, flow in supported_flows.items()
            ):
                return [{"code": "incomplete_scheme_definition", "scheme": name}]
            declared_scopes = set().union(
                *(set(flow["scopes"]) for flow in supported_flows.values())
            )
        else:
            flow_name = resolved.get("flow")
            required_by_flow = {
                "implicit": ("authorizationUrl",),
                "password": ("tokenUrl",),
                "application": ("tokenUrl",),
                "accessCode": ("authorizationUrl", "tokenUrl"),
            }
            raw_scopes = resolved.get("scopes")
            if (
                not isinstance(flow_name, str)
                or flow_name not in required_by_flow
                or not _oauth_scopes(raw_scopes)
                or any(not _url(resolved.get(field)) for field in required_by_flow[flow_name])
            ):
                return [{"code": "incomplete_scheme_definition", "scheme": name}]
            declared_scopes = set(raw_scopes)
        for scope in scopes:
            if scope not in declared_scopes:
                issues.append({"code": "undefined_scope", "scheme": name, "scope": scope})
    elif scheme_type == "openIdConnect" and scopes:
        issues.append({"code": "external_scopes_unverified", "scheme": name})
    elif scopes:
        code = (
            "roles_unverified"
            if openapi_minor is not None and openapi_minor >= 1
            else "scopes_on_non_oauth_scheme"
        )
        issues.append({"code": code, "scheme": name})
    return issues


def build_offline_api_security_scheme_audit(
    *,
    content: bytes | bytearray | memoryview | str,
    bundle: ServiceContractEndpointBundle,
    principal_assertions: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Filter declaration pairs whose referenced schemes resolve locally."""

    if not isinstance(bundle, ServiceContractEndpointBundle):
        raise OfflineApiSecuritySchemeAuditError("typed endpoint bundle is required")
    try:
        payload = _coerce_content(content)
        source = bundle.source
        reproduced = extract_service_contract_endpoints(
            payload,
            source_id=source["source_id"],
            media_type=source["media_type"],
            provenance=source["provenance"],
        )
        if reproduced.bundle_sha256 != bundle.bundle_sha256:
            raise OfflineApiSecuritySchemeAuditError("contract and bundle differ")
        matrix = build_offline_api_security_matrix(
            bundle=bundle, principal_assertions=principal_assertions
        )
        limits = ServiceContractExtractionLimits()
        document = (
            _parse_json(payload, limits)
            if source["media_type"] in JSON_MEDIA_TYPES
            else _parse_yaml(payload, limits)
        )
    except (ServiceContractExtractionError, OfflineApiSecurityMatrixError) as exc:
        raise OfflineApiSecuritySchemeAuditError("contract or matrix input is invalid") from exc
    definitions = _definitions(document, bundle.document_kind)
    openapi_minor = None
    if bundle.document_kind == "openapi":
        version = re.fullmatch(
            r"3\.([012])(?:\.\d+)?(?:[-+][A-Za-z0-9.-]+)?",
            bundle.document_version,
        )
        if version is None:
            raise OfflineApiSecuritySchemeAuditError("OpenAPI security version is unsupported")
        openapi_minor = int(version.group(1))
    rows = []
    resolved_pair_count = 0
    for matrix_row in matrix["rows"]:
        issues_by_key: dict[str, dict[str, str]] = {}
        for requirement in matrix_row["security_requirements"]:
            for scheme in requirement["schemes"]:
                name = scheme["name"]
                for issue in _scheme_issues(
                    name=name,
                    scopes=scheme["scopes"],
                    definition=definitions.get(name),
                    document=document,
                    kind=bundle.document_kind,
                    openapi_minor=openapi_minor,
                ):
                    issues_by_key[_canonical(issue)] = issue
        issues = [issues_by_key[key] for key in sorted(issues_by_key)]
        status = (
            "no_security_requirement_declared"
            if not matrix_row["security_requirements"] else
            "locally_resolved" if not issues else "unresolved"
        )
        pair_count = (
            len(matrix_row["differential_pairs"])
            if status == "locally_resolved" else 0
        )
        resolved_pair_count += pair_count
        rows.append({
            "endpoint_sha256": matrix_row["endpoint_sha256"],
            "definition_status": status,
            "issues": issues,
            "locally_resolved_pair_count": pair_count,
        })
    body = {
        "schema_version": 1,
        "bundle_sha256": bundle.bundle_sha256,
        "content_sha256": bundle.content_sha256,
        "matrix_sha256": matrix["matrix_sha256"],
        "rows": rows,
        "locally_resolved_pair_count": resolved_pair_count,
        "definition_assurance": "local_contract_only_not_deployment_verified",
        "target_authorization_verified": False,
        "positive_use_approved": False,
        "effects": dict(NO_EFFECTS),
    }
    return {**body, "audit_sha256": _digest({"domain": DOMAIN, "body": body})}


def verify_offline_api_security_scheme_audit(
    *,
    content: bytes | bytearray | memoryview | str,
    bundle: ServiceContractEndpointBundle,
    principal_assertions: Sequence[Mapping[str, Any]],
    audit: Mapping[str, Any],
) -> dict[str, Any]:
    expected = build_offline_api_security_scheme_audit(
        content=content, bundle=bundle, principal_assertions=principal_assertions
    )
    if not isinstance(audit, Mapping) or _canonical(audit) != _canonical(expected):
        raise OfflineApiSecuritySchemeAuditError("scheme audit does not match inputs")
    return expected


__all__ = [
    "OfflineApiSecuritySchemeAuditError",
    "build_offline_api_security_scheme_audit",
    "verify_offline_api_security_scheme_audit",
]
